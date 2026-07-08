#include "wrela/IR/MLIRSupport.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/IR/MLIRContext.h"
#include "llvm/Support/raw_ostream.h"

namespace wrela::ir {

std::string createEmptyModuleForTesting(std::string_view moduleName) {
  mlir::MLIRContext context;
  mlir::OpBuilder builder(&context);
  auto module = mlir::ModuleOp::create(builder.getUnknownLoc());
  module->setAttr("wrela.module_name", builder.getStringAttr(moduleName));

  std::string text;
  llvm::raw_string_ostream out(text);
  module.print(out);
  return out.str();
}

} // namespace wrela::ir
