pragma solidity ^0.8.24;
contract PolicyRegistry {

    enum GateType {
        And, Or
    }

    enum Operation{
        Equal, NotEqual, GreaterThan, LessThan, GreaterThanOrEqual, LessThanOrEqual
    }

    enum Validation{
        Revoked, Invalid, Valid
    }

    struct Credential{
        bytes32 schemaId;
        address issuer;
        bytes32[] attributes;
        Validation validation;
    }

    struct Issuance{
        uint256 index;
        Validation validation;
    }
    struct ConstraintConstant{
        bytes32 value;
        uint256 index;
        uint256 attributeNum;
        Operation operation;
    }
    struct ConstraintAttribute{
        bytes32 schemaId1;
        bytes32 schemaId2;
        uint256 attributeNum1;
        uint256 attributeNum2;
        uint256 index1;
        uint256 index2;
        Operation operation;
    }
    struct DAG{
        Issuance issuances;
        GateType[] gateTypes;
        ConstraintConstant[] constraints;
        ConstraintAttribute[] attributeConstraints;
    }




    function basicIssuanceDAG(Credential[] memory credential, DAG memory dag) public pure returns (bool){
        if (dag.gateTypes.length != credential.length - 1) revert("Gate type length must be one less than credential length.");
        bool result = credential[0].validation == dag.issuances.validation[0];
        for (uint256 i = 0; i < dag.gateTypes.length; i++) {
            // Check the gate type and apply the corresponding logic
            if (dag.gateTypes[i] == GateType.And) {
                result = result && (credential[i + 1].validation == dag.issuances.validation[i+1]);
            } else if (dag.gateTypes[i] == GateType.Or) {
                result = result || (credential[i + 1].validation == dag.issuances.validation[i + 1]);
            } else {
                revert("Invalid gate type.");
            }
        }
        return result;
    }


    function ConstraintConstantCheck(Credential[] memory credential, DAG memory dag) public pure returns (bool) {
        bool result = true;
        for (uint256 i = 0; i < dag.constraints.length; i++) {
            if (dag.constraints[i].operation == Operation.Equal) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum] == dag.constraints[i].value);
            } else if (dag.constraints[i].operation == Operation.NotEqual) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum] != dag.constraints[i].value);
            } else if (dag.constraints[i].operation == Operation.GreaterThan) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum]     > dag.constraints[i].value);
            } else if (dag.constraints[i].operation == Operation.LessThan) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum] < dag.constraints[i].value);
            } else if (dag.constraints[i].operation == Operation.GreaterThanOrEqual) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum] >= dag.constraints[i].value);
            } else if (dag.constraints[i].operation == Operation.LessThanOrEqual) {
                result = result && (credential[dag.constraints[i].index].attributes[dag.constraints[i].attributeNum] <= dag.constraints[i].value);
            } else {
                revert("Invalid operation.");
            }
        }
        return result;
    }

    function ConstraintAttributeCheck(Credential[] memory credential, DAG memory dag) public pure returns (bool) {
        bool result = true;
        for (uint256 i = 0; i < dag.attributeConstraints.length; i++) {
            if (dag.attributeConstraints[i].operation == Operation.Equal) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] == credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else if (dag.attributeConstraints[i].operation == Operation.NotEqual) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] != credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else if (dag.attributeConstraints[i].operation == Operation.GreaterThan) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] > credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else if (dag.attributeConstraints[i].operation == Operation.LessThan) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] < credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else if (dag.attributeConstraints[i].operation == Operation.GreaterThanOrEqual) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] >= credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else if (dag.attributeConstraints[i].operation == Operation.LessThanOrEqual) {
                result = result && (credential[dag.attributeConstraints[i].index1].attributes[dag.attributeConstraints[i].attributeNum1] <= credential[dag.attributeConstraints[i].index2].attributes[dag.attributeConstraints[i].attributeNum2]);
            } else {
                revert("Invalid operation.");
            }
        }
        return result;
    }
}