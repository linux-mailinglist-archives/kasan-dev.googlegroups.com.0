Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB46MSSKAMGQED2VEZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3290052BFD8
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:01:43 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id d12-20020a17090a628c00b001dcd2efca39sf1506189pjj.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893301; cv=pass;
        d=google.com; s=arc-20160816;
        b=VbGKBwep513RyqY5inKQYBZPNCL6LERAvsHV+M0xu2BU9A65eSuc9I7Fw+65rx+QTO
         dbYs+sG4ezSO3zoFuHYGZ/OcMPv0r6PLzDfr7OKyzJ+I9YoxPzbT8nmMt0u1m7npJesD
         Q/sYDcTw2PYuUqND2AiWH7P3s17RNNR0lH+4ZwGjgntVCOq4+Yt0Jp/lVFVZN405mpOk
         XTrG5W4Zs59+kGWJ7XPXmlyXbzcBgNqimX+cCNptNaTKab7ORPnrB2t3QSGR17H3Wk82
         nqrQ2fuPyOdIV0hOu0ZD4L1njHha3R6Rq488ZN3Pa8H+4L3lFGE3zeFa+BV9o51MzvGV
         P5rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=G1xDcs36JG7OzpTjoQnZ3aI07tVvo/37K9ecom0MVww=;
        b=f6VUfIw66K1nQFgCrCL74AsQ/84nPa6ZVjArI+PmQqQHwEaBnf6+nRYsyNVb6t9c8d
         OhGbv5uyGIePpY69m9knWyV1gM8GYw36IbMAtXizHgOj9I5yxYcRaoGzZivfSWPmmhLF
         CvuB5O2Kl5z5AIFCC+pruAv1CuzhvLJvDMz8qVWdnYccVKr6qWeNqFHY+TIl8rMo82hk
         LfFmCqHGd+jCDDCoRs2fGxOxEHA4bNj66IX7vs6XMsOMGJyd2clmSD4sVpqNDD8YBciP
         M6yF3SpsBYUtFMOdseJolFTT/TkKQ49Uulf53u43QV5ZV4ssQsVh9SdkumiH7DqA3OG4
         lVMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GTzkF8O5;
       spf=pass (google.com: domain of 3ciafyggkce0sapinedkvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ciaFYggKCe0SaPinedkVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1xDcs36JG7OzpTjoQnZ3aI07tVvo/37K9ecom0MVww=;
        b=U8UQW3HPrSINbSZcJlrQCSDrMtE40WEG3UVpeRnVNULBN90Pr0P6wevPUjhKLKLVK1
         BA1vY9p86kfCgttc3Y759vVvm5sLjqipkeOp/C6YzzH98c6gdMXrqFj2S7Hd+ibYKKJS
         r3/aSrZNsXMmADTZvJYVZO9qc8rTb+waprUmBIWeVpw35rIlFHwQSyU3f7Vf4RltGev0
         dSWp5nzrYMKfyqyLVEyIKG9YsrqYzNzaiadgB2F03xx3VGgLbIuLSc8qbwj0GyPzQngx
         Ta5O9jvvdfhOARZ2l4lfIJepfzH0bFmTWEF/Eh2FQpISMsM8WTF4rjDVZU4V8jXHzdle
         y79w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1xDcs36JG7OzpTjoQnZ3aI07tVvo/37K9ecom0MVww=;
        b=IY1oYZZ/8Xgi3uUxyCzRcrEqKGF0YLSaugB6hoeIRz92JqYQpnPTtREj9FWNBo1A47
         WQLrj8043NmFYAl3YXLASE5xdJwpzEiNHd5cdOLo4nDG3J9DLo6CO3VKMLAD3OCwk5f/
         VtsP5m+c1Z7a802KBSuJt5cn8K/GKBIL7Mj9EnOHhYywgdkyLoDBCLCXl5Kw1/MFcg3/
         401z2XGQC6CkmpLtxwecOVMsHpKruIZeeIoLVyovZ6dWciXPyoW8mSwrTxuZ98qrkCA5
         /FlIrGzEQthszPPBLLQbb4U/+tX4Yz6TGndFa+VPIdk/Nuy32kKU/PjWGyjUTAFrQ87g
         +Ymg==
X-Gm-Message-State: AOAM531bK/cmfj3WgEfpTt/gCG4yDYUY2r/MwmnF5BCNp/nOmmb4/LEs
	8exrbyyElZc4b51dU+RBdmg=
X-Google-Smtp-Source: ABdhPJxInR03atpIynqaL0nBflDtSyDGDPE9KYqkUT6trtiQjEipCiOnZFGWmQwEG+ZzTayKtrUhrQ==
X-Received: by 2002:a17:90a:8b91:b0:1be:db25:eecd with SMTP id z17-20020a17090a8b9100b001bedb25eecdmr419569pjn.10.1652893299645;
        Wed, 18 May 2022 10:01:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8c:b0:14d:d65a:dbdb with SMTP id
 m12-20020a170902bb8c00b0014dd65adbdbls175583pls.6.gmail; Wed, 18 May 2022
 10:01:38 -0700 (PDT)
X-Received: by 2002:a17:90a:c48:b0:1df:6210:48a0 with SMTP id u8-20020a17090a0c4800b001df621048a0mr361637pje.119.1652893298899;
        Wed, 18 May 2022 10:01:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893298; cv=none;
        d=google.com; s=arc-20160816;
        b=l9jMU25F709YCNsc/EnD+CD/b7R8lrKhHN0NA1Z6J08+N22ChH5sgba5sxT+h6BioQ
         /fk7/X03L/jhGeWl3HDG2sUtlkO5ASGgqgyArAriH7Wohw3fWl4GIC40pet8p9BOhuld
         F8WCNPAYDJHSlJkJ0dA7+/Zc6P7s8UnzpdiJEQ2T3oycvFOiv+b5r3SMgRJgAF9djEyq
         rXg92SxSMpJY6dHTLT2eggSj9PLOz/PHvExF4HeZS+ZWEdntIQ+t8bqPtr4yheLRutb4
         nB/Loy75mmUMEpgtq3iTMv+9jkl61NBvgNIwRhIinhz4i8a9Y/VSKFnEO+ASBznsTB89
         MFUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=21gji5A7fyf+LOH7W7vX2Ngr8AGXxxWBQWpGLTWRGhA=;
        b=Vs9fQSP5vvFvVVQTGmSMMIrVGx+TDUOQoePpVZ35dKEAakDcUQ+mtvoMpSRiP6QVsv
         6pSOFkIGEEFNIiHuhWj3jbRpHz9tncrc8gA5P8Zam+lrHR3lNwRcKVUTvGphstrjn1dP
         Rc/biGjYu7X37s2ZtdDioCpWjhVqiUrGFGxVcLXI1Iko9u4QKV7TJIPFvdr4ZTxJ1ePh
         g9sbdfLpU3pN12If1HRoMe3Z3Hlyh1WsehNTVU8lw+rSt4G4LqdjyMO7mKGhfc5HHcrt
         HBGIoOI7dC9hjiU6lYn3aQ/oLloi8FDyurDiwHOplCqLVTY2NtbclHOyShrVmJ1Rb96m
         OQ4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GTzkF8O5;
       spf=pass (google.com: domain of 3ciafyggkce0sapinedkvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ciaFYggKCe0SaPinedkVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id q7-20020a056a00088700b0050db7f22ea1si179813pfj.2.2022.05.18.10.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:01:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ciafyggkce0sapinedkvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-2ff37db94e8so23869397b3.16
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:01:38 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:a94f:2cb3:f298:ec1b])
 (user=dlatypov job=sendgmr) by 2002:a81:2f8c:0:b0:2fe:ed42:21ca with SMTP id
 v134-20020a812f8c000000b002feed4221camr399767ywv.120.1652893298194; Wed, 18
 May 2022 10:01:38 -0700 (PDT)
Date: Wed, 18 May 2022 10:01:22 -0700
In-Reply-To: <20220518170124.2849497-1-dlatypov@google.com>
Message-Id: <20220518170124.2849497-2-dlatypov@google.com>
Mime-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com>
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH 1/3] Documentation: kunit: fix example run_kunit func to allow
 spaces in args
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: elver@google.com, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	skhan@linuxfoundation.org, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GTzkF8O5;       spf=pass
 (google.com: domain of 3ciafyggkce0sapinedkvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ciaFYggKCe0SaPinedkVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Without the quoting, the example will mess up invocations like
$ run_kunit "Something with spaces"

Note: this example isn't valid, but if ever a usecase arises where a
flag argument might have spaces in it, it'll break.

Signed-off-by: Daniel Latypov <dlatypov@google.com>
---
 Documentation/dev-tools/kunit/running_tips.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kunit/running_tips.rst b/Documentation/dev-tools/kunit/running_tips.rst
index c36f6760087d..da8677c32aee 100644
--- a/Documentation/dev-tools/kunit/running_tips.rst
+++ b/Documentation/dev-tools/kunit/running_tips.rst
@@ -15,7 +15,7 @@ It can be handy to create a bash function like:
 .. code-block:: bash
 
 	function run_kunit() {
-	  ( cd "$(git rev-parse --show-toplevel)" && ./tools/testing/kunit/kunit.py run $@ )
+	  ( cd "$(git rev-parse --show-toplevel)" && ./tools/testing/kunit/kunit.py run "$@" )
 	}
 
 .. note::
-- 
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518170124.2849497-2-dlatypov%40google.com.
