"""TR01 is a separate stage obligation, not a fifteenth legacy relation."""
import unittest
from toolchainmark.integrity import CarrierSnapshot
from toolchainmark.transform_admission import assess_removal_postcondition
from toolchainmark.relations import PAYLOAD1


class TransformPostconditionTests(unittest.TestCase):
    def assess(self, source, followup, **changes):
        inputs=dict(removal_requested=True,transformation_completed=True,
                    postcondition_snapshot_current=True)
        inputs.update(changes)
        return assess_removal_postcondition('string',source,followup,PAYLOAD1,**inputs)

    def source(self):
        return CarrierSnapshot({'kind':'payload','value':PAYLOAD1.hex()},b'source')

    def removed(self):
        return CarrierSnapshot({'kind':'rejection','value':'absent'},b'followup')

    def test_completed_noop_is_a_transform_inconsistency(self):
        result=self.assess(self.source(),self.source())
        self.assertEqual(result.verdict,'INCONSISTENT')
        self.assertTrue(result.exposed)
        self.assertNotIn('followup',result.observations)

    def test_verified_removal_is_satisfied_without_tested_extraction(self):
        result=self.assess(self.source(),self.removed())
        self.assertEqual(result.verdict,'SATISFIED')
        self.assertNotIn('followup',result.observations)

    def test_missing_or_stale_evidence_does_not_expose_a_transform(self):
        cases=[(None,self.removed(),{}),(self.source(),None,{}),
               (self.source(),self.removed(),{'removal_requested':False}),
               (self.source(),self.removed(),{'transformation_completed':False}),
               (self.source(),self.removed(),{'postcondition_snapshot_current':False})]
        for source,followup,changes in cases:
            with self.subTest(changes=changes):
                result=self.assess(source,followup,**changes)
                self.assertEqual(result.verdict,'INADMISSIBLE')
                self.assertFalse(result.exposed)

    def test_wrong_payload_source_is_not_a_postcondition_counterexample(self):
        bad=CarrierSnapshot({'kind':'payload','value':'00'},b'other')
        result=self.assess(bad,self.source())
        self.assertEqual((result.verdict,result.reason),('INADMISSIBLE','source_payload_valid'))


if __name__=='__main__':unittest.main()
