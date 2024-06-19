namespace GerKiss.Exceptions;

public class ValidationResultModel
{
    public int Status { get; set; }
    public List<ValidationError> Errors { get; set; }

    public ValidationResultModel(int status, List<ValidationError> errors)
    {
        Status = status;
        Errors = errors;
    }
       
}