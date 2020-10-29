Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYUB5P6AKGQEHUQM7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E0FB29ECA4
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:24 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id p3sf1972899plq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977443; cv=pass;
        d=google.com; s=arc-20160816;
        b=MP20DvgVOkwPMgwIhgPdd1vcmqnBo41Qb/AnCP1rWV6pzDtXpdLoOCxCjUGhBQ4A30
         LR3Fu9zx4XkdcpJHZhtURBpAym9gu9tDgUsnmjyLCzEqkzFpmtWbp+4XiHg3ngxXy0JT
         zB4ukFwMe04Pj7v6Ezeb7ugpZYAAuttCDANnDSnT7U2Ls8FTDd/zNPx3uw8QXkg9DtFv
         8RnLNLOUkbrrRMVCbOwaAacEmAvg59KtCV1DKZvya7wt8XKum8DcnE5jeLFsdj/zzWLE
         egW47dRUeBpyuN7viLXLthJqvTWwZy2fSk+ibtv1IY57ehwi+m0aDiK2Kj0Pt305HYU3
         Xgtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d0cTXgCuKHpWj7mnYixNUY3Bb40HXdUZgz5kN5Ec4Gw=;
        b=if3GMLP6zn1SdZd6NBbxNc9rT6Cp/gO4p0qa3b9reA1RW/hvs0nXEs8PrC5ONn0+aY
         Ep9JjYInR1IM1wOm8iOANHrhMEdcypuCv0UaP67LjtSCysVp7gr4CEXHMb2BfVo2pf/b
         1EmULwNuGYJp8lEX0p9f1gzHiZNMJLNoIk+VFurUIxd5O5Eo6BbZheEJYR6SD7skXQbG
         InNIaAIGLm56asZT6e6ZoHzCzEwzKYOGTs8vrPDl4xQK1Qq6WRpGUsHgm8hPlxGCWAty
         scvCFexbUxI8b+25WefX4Ie8GZKlvSyun8tyyhx03hHOq1m62KD3bv+wHHb2FggEDlPr
         wnrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rRA+MGMd;
       spf=pass (google.com: domain of 34ccaxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=34cCaXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d0cTXgCuKHpWj7mnYixNUY3Bb40HXdUZgz5kN5Ec4Gw=;
        b=J9OLpFfiW3sGdDTb9/mG9+wNF3Ay+3e5b+rDazdm5gmKHeTt3RFUj6jWyXp4eIm4Hh
         32v2m7HWHXWOFUZWlPnV67Hh0wv1iBhKfqDGE9smMg2uDDBVVrhrQ9YbLD20RSChFlKy
         p9eVZQAEsYoAbQEyrRJ8yytvsl0m8L9J/Wu+ZmGBESPjGdO/46K9t+4EMKQc05yIUiQm
         c5RuSJWDpBWwKni7h55o4HQuTY55pdjN4Cr/ckW0M8NpMPrqA6gDCxfe2JSXmHGICVB5
         d2Qjq+iokMz2/htYlj9kkGAC0hfB1tvCmAShDFJoDrQuTpV5qp9FR+Uc9jXd7HnjJ42/
         oijA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d0cTXgCuKHpWj7mnYixNUY3Bb40HXdUZgz5kN5Ec4Gw=;
        b=FlSBZT2hSb1ecs1CbnMGwr7vnPnCASrAbM8pqhxBJWnHyV2Wf5+V94dLha7PH62LmZ
         Ax5FhQC6+eUJTcvx9UTrjnVR44TOnrzu4w65d+ky3yuPnbku/Fngu+5qL9UpmdEs+bWg
         EmDDrOxCxkYJwK6gJ3ThwzDk0vsVy5bjT4IeecHtI0h8/gjtwHTgEH1CVL3ocFXwqpxq
         PSEQIRASKUfXG6YUXMaPcw5a42G69mwvt2REx1+jpuspTK7kPqSJnqWAA96SpYCH3Jz4
         z6LZ352vXscZ+/Q6DXV5ptYV4fStVpB4wfmbO0U31Mn1updTqNGVbpjKBL0r5dWckdJ0
         NEuA==
X-Gm-Message-State: AOAM531Ts8F9d6IiGPvmSRFZcdPBVFqipc0OsCAuhDvVWMF9hO2DX3BD
	7k+GH3VABMgRkC6Pi1TYC1g=
X-Google-Smtp-Source: ABdhPJwqtpgAC6lvWhTGgLbqN40bal8D7nTLt0cEtTVpvNb3H3nBFIIJkIxcMzIravgRQGYQ/bG6mA==
X-Received: by 2002:a17:90a:aa85:: with SMTP id l5mr4496136pjq.119.1603977443023;
        Thu, 29 Oct 2020 06:17:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b8a:: with SMTP id ay10ls1283076plb.6.gmail; Thu,
 29 Oct 2020 06:17:22 -0700 (PDT)
X-Received: by 2002:a17:90b:297:: with SMTP id az23mr4554998pjb.71.1603977442416;
        Thu, 29 Oct 2020 06:17:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977442; cv=none;
        d=google.com; s=arc-20160816;
        b=lZvymoz9BAtAYpIdzlc1L2mMDRlnF7TbSi4bUiKcmYd6Um/9+afJIF5dOi0iU3FFu3
         nF9oF2HLo3sA7moC10O7aZmt9Zv7xiAK+cGPsj8R4XbBoqNRrWQduQ07h9KKxw0QskeP
         DUgFDRad1/K0yjicZrvHbOW9R+Z8jd2okL+Mi+mx8WLkM+mhmGcpP8xPwWL4b28B2FSS
         D/7PnKKHOMT4hFdyOqJ+lJ+t1nVRD6BiK2Bugdn0WialcdYzWV0hIK5ccn6+MOFYCSNU
         jHEJSD7DWbQBG5ugCiw+Z4K9kKcH1Q3P05NRyJCezdpUUI7gNGDFKmDhLqG3K8Qh96+P
         7U4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hmbKrgrrAV+ZwrZ7GWFGPrZaCp36du3w8RCEfMZ8hak=;
        b=DXTaAn/TjcNmsxLbRp0LeqHAn4e+5QMWfYuZXjhhXzoP3o14n3pRHaV8po0EYDDvSP
         NpGbzjYStezyFLg2vpFo4Imjoettde4IDqwbsr/DVwNlC6SzvTa9jkxtPeP2pSkRePCS
         GY7ALk0Pz8lL2JR6j//CNg6jHfVvGNrOTIpOi7hdgB4HIy8dDsclnDfmK+lpezT+aWpw
         uhtNXl7vFzR+m6k5s2GtYATf+iWUphHLrpqPL6+zBDj1+Rt7vJn5eoCXjtETHCnh7utC
         CKtqy/Yr+hxfXEsetueH/bLipn3WZdpS+bB/FxPuScihAf6Id6O1vEdFbvL0VbP8U9r3
         66Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rRA+MGMd;
       spf=pass (google.com: domain of 34ccaxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=34cCaXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id j63si181768pfd.1.2020.10.29.06.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34ccaxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e19so1819824qtq.17
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:22 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:943:: with SMTP id
 dn3mr4211962qvb.45.1603977441430; Thu, 29 Oct 2020 06:17:21 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:49 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-10-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 9/9] MAINTAINERS: Add entry for KFENCE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rRA+MGMd;       spf=pass
 (google.com: domain of 34ccaxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=34cCaXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add entry for KFENCE maintainers.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: SeongJae Park <sjpark@amazon.de>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Split out from first patch.
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index e73636b75f29..2a257c865795 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9753,6 +9753,17 @@ F:	include/linux/keyctl.h
 F:	include/uapi/linux/keyctl.h
 F:	security/keys/
 
+KFENCE
+M:	Alexander Potapenko <glider@google.com>
+M:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kfence.rst
+F:	include/linux/kfence.h
+F:	lib/Kconfig.kfence
+F:	mm/kfence/
+
 KFIFO
 M:	Stefani Seibold <stefani@seibold.net>
 S:	Maintained
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-10-elver%40google.com.
