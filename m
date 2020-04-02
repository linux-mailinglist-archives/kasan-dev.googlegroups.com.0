Return-Path: <kasan-dev+bncBDK3TPOVRULBBO46TH2AKGQEP5RZLQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8ADB19CBDA
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 22:46:52 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id l137sf4505884oih.21
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 13:46:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585860411; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dgo9tHrvKnt2syaAs+kgjuglPKaVba5Jpt2VsDvIFAIyAFv3n1xFtaw9DbQu0MZiDJ
         duqO4jDTzbJmgXRQwgQmNKOZQNFC56g6AuusEqS7AsRk2beLCMYD0Qsjd5pLqLBk+iZ5
         /dAaRv5TGEQZNkMAwPS3fHuxsC+TbEALCwCuOSHhv/dvZ1ACZM/C4iYlZX855pnaZqUt
         DflRHKpAAa8c914hlP3Vt8bEpse1ucex2Cjr/8ZmGydseAxeaxGQbkqA0PtUB4iYeEwG
         ocMKJDxX0BXEyNa5sBOVwo/b0jHe6kufWcERLAb0Wl1JalHDn2RqwDuQIF17gIgvUfxh
         N0Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nzUbtXgiwxVSpeU4mU78UCKbkp5YDT6isnzJPWcNS5w=;
        b=YIiJFAYlUAt3cDTP0bABfO4oF3m/35WubJ6iZxC81UjRffve3xxPEx9B/GXhraCvmD
         VHG5uh+uV1Iboh+wZ04yoBlDGaJaBueuDWVG72dJmVXbn2oU70QRx7pw4nzkTgytJshf
         MWSWzg1AUUoLmYTt6QNhPfnWVxuhsswh65EQ6wbqNJ2WkJl5ULxWEBSH29s/bSmbKchf
         9TFxwGw7aN0YEBsqUiD/D1ALqGWGok6U7DRW9+ErH1eho/v/c2eXmGfzqXn97LTgo3ip
         lr98I3N0hajs6RLBLrvB6aK38MJVUPfQU2pd+7ZCZjpfEVoIY9cXCAez1VRPozeMjv7u
         raaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uLkmlZPn;
       spf=pass (google.com: domain of 3ok-gxgwkcesgevfunysbafbtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Ok-GXgwKCesgeVfUNYSbafbTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nzUbtXgiwxVSpeU4mU78UCKbkp5YDT6isnzJPWcNS5w=;
        b=oCV08tYs8CuDpt9ncsOzFS5MwxhT5Kq+d1+mlGFYJRVO2GeqoCvNJwuHccvxFcMXBm
         BLKD+yIf2JXk0twXkJjiCFr+ZyitubRk7zIl2ZhmLNCkI1V5BiFjWxiNzEVrmXrzzg+O
         3bZQn5RTXfLQI2TDtL2bC3RyH/4QPQcHqIRuIHeoC3+DJC2w3MEpACEvs71Rb8oXyGjY
         y8z/m6giIeQ+zwZCP/1VL6AMvU+sUynxSjIg01EZlA6HvqoY4MBu5K/+Q24Z3kO+/+D0
         90ozuF+uMt8NJQ6oPTksXIREvogy+Nx5BW/yC266zHELEq8wIjM1wXfMaoid5t+fFx0J
         ms5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nzUbtXgiwxVSpeU4mU78UCKbkp5YDT6isnzJPWcNS5w=;
        b=BfFl3JBj2hXvH0FyGSbdoZZkoBbZqmdpQuw7FFh4tEILss7GeJPOMsYj8dd+tBIPOH
         VsQ6H5R1Rn2Cj5QI4uD+Lx/wfUvo66+ND0yjWNQ8hLc2uLARpIkOPyn+6v5fbxJpWWAq
         NiKyKQUa7LNvnJDCY+BpPvCnzaoZN8hRegbE7YxMV9vLPKQuA/dqazIQEg32pSi1qde8
         N2GcQrjQKb/bK+SBBDGHNMMaGDdtyQl7feg4y3Jnbqtqc4F9PKhrwvoqkgYrTkcKaJ09
         FblogS7fS/kTMf2KAHEomptIsY+U9rYqOUAIeSAyxcF3uRXRLkVUh8rEm4SPEbKoRzRn
         JD5A==
X-Gm-Message-State: AGi0PuYKYlNYqSbjPcnrmQveYt6rd+IsaczzWhKk0ATJM+66Vntcp+yE
	Qe4HU0cLsik/HKuBc+jg1J0=
X-Google-Smtp-Source: APiQypI0rux1y8PsM+0odGz0o5JMttjwB0lxQJb9CJ80ASl/Ff5Lvwj31FOgB1NHkIX+uTGQuRGREA==
X-Received: by 2002:a9d:3a62:: with SMTP id j89mr3634981otc.45.1585860411657;
        Thu, 02 Apr 2020 13:46:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:467:: with SMTP id 94ls2153879otc.11.gmail; Thu, 02 Apr
 2020 13:46:51 -0700 (PDT)
X-Received: by 2002:a05:6830:1190:: with SMTP id u16mr4108143otq.83.1585860411272;
        Thu, 02 Apr 2020 13:46:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585860411; cv=none;
        d=google.com; s=arc-20160816;
        b=ar1DgKtN3FdYpLDkkSJdYGjzN2G8Y6ohKd+Mk5oV1okqSjuiy2WMyxlRdR0dLxZJKY
         bqJ3m3NEPIXQdzmS1AGR7usgrsJ4KVyeG5pEZb1J4qcmO9lcPLVACzITwVqaPFrH82U/
         +COLh2EUPpOn2YEXrY3fo/pxI4GxOqE4o2oAbahIGgUlhg0XfFLOi5+CH0MfUSOytHlU
         6PjYQd38nfQ+P5UTq7zScL6SxGyI3ghGPmVD+gwzrdXBymy4WY+Uc7Yd2zQpwIdvQhVI
         YoNqyC5oJIRDLDkS4QHUEVUqPFz9ilpmseDlmfJ6goCTYJFLUgBldZ8/G+xOFOO+x64w
         K0tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=onaohHgaOvnldbVkQ7ukvTTvpY4LJI7aLjqWlCpDam4=;
        b=QT4tS1rPSg0X0jdfdPN0YtIIg4hqywtjZcVdlgJ2GQ8BwAAvay8F84Ny3axducTuHn
         XqMzi1bbkj3waLbqRlkrDx67Nh0kpKx4DIQHXYJ10YqSCQeqr6wp2z543j2fnhCyVOoI
         fmBOqeh6F1GogEIlUExRtM1bHCDO8JSP5y/cPcGB6u9GdQfBdPhGNZwtTjTzcdR1YsxM
         LmLoduYhEEht98NXw2rsYDx63EhwL/ake+2aeH49zRnKOXxxdpDwwPaTPnbSporC6qiy
         rTx/aGvSGaegBWiRB/5fMvmKMFJKKFtbnsH++9t3b6JGbsIsJvSCnsg0ncvC7ohR0r01
         VaMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uLkmlZPn;
       spf=pass (google.com: domain of 3ok-gxgwkcesgevfunysbafbtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Ok-GXgwKCesgeVfUNYSbafbTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m132si465357oig.3.2020.04.02.13.46.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 13:46:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ok-gxgwkcesgevfunysbafbtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id q15so4057063pgb.4
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 13:46:51 -0700 (PDT)
X-Received: by 2002:a17:90a:d3c7:: with SMTP id d7mr5575934pjw.169.1585860410527;
 Thu, 02 Apr 2020 13:46:50 -0700 (PDT)
Date: Thu,  2 Apr 2020 13:46:38 -0700
In-Reply-To: <20200402204639.161637-1-trishalfonso@google.com>
Message-Id: <20200402204639.161637-4-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.292.g33ef6b2f38-goog
Subject: [PATCH v4 1/4] Add KUnit Struct to Current Task
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uLkmlZPn;       spf=pass
 (google.com: domain of 3ok-gxgwkcesgevfunysbafbtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Ok-GXgwKCesgeVfUNYSbafbTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 04278493bf15..7ca3e5068316 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1180,6 +1180,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.26.0.292.g33ef6b2f38-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-4-trishalfonso%40google.com.
