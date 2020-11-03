Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55UQ36QKGQEQRBUDEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 409E32A4DB0
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:26 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id m26sf7478921ooe.8
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426359; cv=pass;
        d=google.com; s=arc-20160816;
        b=AlyGeVafhg94EoiFXA5PBxYbkoFgG4vpgnf5TlVtWVzdgRlShc7vHelu/dg0sfV0pJ
         cY7v1IfVBU7D1PElJ0rkynSodGyd5kocT2kcYq0UZGbo5mQJXwbFdnuDrLeNydXToXwF
         0z7KKJh4C7+CUnpmzC/WzRDWEZj7TsD6dghOpAbYq+g6v1KHFv0PoHpqzd+8RgYPQWDG
         b4uk+nlbOSxvOPs2YwS/iINzRLu9qFqa+jOOnqSsylLX3iAeR9y4nQb/Qp7HqeCUAlat
         i9YgYPEm4lk1MTGiYd++B1FheL5HmA25lsIxnHeTrDNrZpdsS7F18kS86coVQIvo1zd6
         Eezw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FSwp+hLPehjfc2Vrq05R09vpLOWLm7hPSJdXQfbda+c=;
        b=K28cywHN35LNuwl8AoblV789hUHB/c5E3Dl6vYz2CtDK8+bsG7pAB8MDuvC7cw9MP0
         0MqaMt3VFcSqs8IQvxaHekRpfAA5tlkb6KQxGCSszwzv7rb5oxAnmWNz5VjMpnLoXcsn
         w2uEqv6QOZQ+JgSUBKNJXXd2imnm1CjU/Zqi8VmAi2Exiq2+Zy5AO2Xs/vdnKCpPRv11
         b5He9hSnzsXG7UrtVeisILyT/E0+IAlIGkOwIDrd5++lh+5e+G/X4yhVa9y6rJuhrjJb
         An0doMf/N68De3yAqxVOs+MS5M3AGzAIbYgYZbFj+kVp8+NHpD+u1ugQbyFeQ3VVxIj7
         95aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLDWNHN6;
       spf=pass (google.com: domain of 3dpqhxwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dpqhXwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FSwp+hLPehjfc2Vrq05R09vpLOWLm7hPSJdXQfbda+c=;
        b=cL44ROVrGASwNP/K7AlWoU+3ZgJ08Z0u1SXMLcraJ7tAXQMP7a5Y9Fq/5MOJj9KCUJ
         LbyLGyfHNhYFFL/MQpHiOiTXmrIjnQooE0iNB0XuBnKOz6DGeHBGWQZEtwG7Nx1ES3kc
         mVOPCZG+7Gxpen6G1pMdIZwn2yEYKtJik3164qwEHPjetC6ojHvAdy9KnPjwZAKoM+hH
         XiWDU83kUaVie7LjeM8B0dBCQcCkqCpHC5jYoGBpLm7Q0n7P4mW1EMH7XoTtgarxEh8r
         GY03yU28MZXGYKlVm65kcr0791H453dRRYkRtFphd4DgckQJSC6EefsYwCUmG47JuFrV
         zLQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FSwp+hLPehjfc2Vrq05R09vpLOWLm7hPSJdXQfbda+c=;
        b=QG+5z0itp9M8y5AzQU9AcsTz4JE0Ieoglb4kVqOz/mziPzpvFQEmePWyhi/y+iPYpA
         A06a0pwknWppXlJ15243v+MFtQJRvLAjgM2th4Xc22llTgP8gHPn2CWtZKM5h2Vw7lDK
         lPCu0xSpZQ/X0nk/twMtxp80F3AfT/YzevBwkD7Nr/r9pRY9oDUuPmlWcr1EZqtJQwKA
         iqeDD9IMc7O68ueNsbpDP5OKIKpP4Bfj04UITLMQUfhYqJux2b0/gCAamWoiuEFod5uR
         THTPrxrCuib0x4mBetpjFejQHFapV08FzCiW8nR/Fh4/kZTFcNRkteKbg3yhXqXpmXoi
         El2w==
X-Gm-Message-State: AOAM530TUnk2LbopF0zFvxSa8WbYZauciH2sZSkyx/rk7ukXT7GrZj3F
	3OOSzDXcLWuwTK6DT0L7gjE=
X-Google-Smtp-Source: ABdhPJzfMOWMnmfuGS2jZCKEMWmZA9wqp0ODztv3ojBHv7YwcpNmBxh6fzo+NKhdi0xcc5ouu86cwg==
X-Received: by 2002:aca:f0c5:: with SMTP id o188mr191703oih.95.1604426359696;
        Tue, 03 Nov 2020 09:59:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d0e:: with SMTP id v14ls708641otn.10.gmail; Tue, 03 Nov
 2020 09:59:19 -0800 (PST)
X-Received: by 2002:a9d:5552:: with SMTP id h18mr16875171oti.311.1604426359329;
        Tue, 03 Nov 2020 09:59:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426359; cv=none;
        d=google.com; s=arc-20160816;
        b=FY4yeKBLMVGYg/p4S2v/PAzoEPABdyR+qHqFY44gYvkFFBQc7+xCyHACFLG5rcH5l4
         /acF6bt22Cx/7dXxvPN4+q9gY3IaAvpWYdTfvOHH/wIYmlCJNQuKWMUzgZu9+IdvfeUg
         4fDFNFkbG+0vq8W6rLNUmhSoqeMaCya+tWWjCwat5kJkywmpfKbaWCf/SS0p7VubtxlA
         liW1k3rNlIhDgVWwl2qOzFfM43iuwrciyNJPbD4Mn8naH6cH1LjNGbfgtmab/0x/QVVd
         nf5o5GtbgI4MehFgTMSY/n1Dm9/h538HhPo2PithBV6zcbLrhFljyy87s7jY7MH0ilYn
         HdyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CyzBgJt6/thndXzzWyuMyy394G827nuVvC5tSjcPYlU=;
        b=XbDGgc9f69xih+pXD4DnhQMzOsM9tNW4YT3+IHmUIWiZiFXuZ+3NUcLD2onj1aoOhB
         3+aQv4WVYg43pfRD1Qz/pt7i7j9JmAFCqbmFuGREOkPot4vLMx+Uq+VHSlvSypUwvOG8
         5FyrQoBgQUL5IjFVLs4zfzgoQyzAxFvqtvt2xtpmDtZJOvOVaayuUKr973pWE4JeGWLX
         oJjlUqasuwZatpx+WyTrt2ClgNZ3THixSLF93FrtH7TPGISEm9UKTZj4q7UcoF17mkjZ
         DmmxIImicnbJLhZ2KqhsftrR56vejFA2Qy5W7ZEAFDSYOrc0sl7PyeIlO2liCSCgGIWZ
         wmzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLDWNHN6;
       spf=pass (google.com: domain of 3dpqhxwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dpqhXwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id v11si1354813oiv.0.2020.11.03.09.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dpqhxwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id z28so8606248qkj.4
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:19 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:43c6:: with SMTP id o6mr28340543qvs.53.1604426358730;
 Tue, 03 Nov 2020 09:59:18 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:41 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-10-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 9/9] MAINTAINERS: add entry for KFENCE
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
 header.i=@google.com header.s=20161025 header.b=wLDWNHN6;       spf=pass
 (google.com: domain of 3dpqhxwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3dpqhXwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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
v7:
* Add asm/kfence.h [reported by Jann Horn].

v4:
* Split out from first patch.
---
 MAINTAINERS | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index b516bb34a8d5..09ad4771599d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9733,6 +9733,18 @@ F:	include/linux/keyctl.h
 F:	include/uapi/linux/keyctl.h
 F:	security/keys/
 
+KFENCE
+M:	Alexander Potapenko <glider@google.com>
+M:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kfence.rst
+F:	arch/*/include/asm/kfence.h
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-10-elver%40google.com.
