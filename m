Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFFP5T6AKGQERUHUSXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id F202829F502
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:16 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id m11sf1649810ljp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999636; cv=pass;
        d=google.com; s=arc-20160816;
        b=cwoHPNu9ACAUHiBU4lm991EtIlC6MrZQptz+fJl2IPcDENTs5HQ3l6rdg/M/LXCz62
         gXa23j+BFZLSh0L+TZ4mYUcVPoB+KdIKBnnMv/qiJr8D3pCIYHJf8cDd4e7wKvly2no3
         6XmX2o/YLqaQMlEg15GwBx+cycjIIse+V81Y6UlIM+ctZ6d+wPVcMyMwq5SaxuMhSzz0
         xV7HVWatcRAN1lmApWa9a9PiDjaJD+TzwwZrKfqKgBZsoATo0Ecbp893h0doW+Dd+OLZ
         TmnItiI6ZzK/dPADMODo2WuLHqqEQujlvk28SXVkOqvIk5+eAi1wLOQyxGpNd3mG/u5u
         Hrjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=w9uIiZ0eMIsaowuWU9ykseC3CK79V6//V8WNCNkgQcI=;
        b=wMQ6BvplhVRY1YGvEVNRKA/TOjtKnR6NWg6vC2zM+MsfNom1om3Q2fTE3M4v1qIos2
         H5zDYaAh3+V9h6PRhv3FPfu4YOD5FtIUMe83VvTZoK9X+dIp/aYtw70wZgE+RhTbSqXg
         yKIdpIOSkXszdiqh0vZjF2oeATECds0kYg6m7+GEkahcc73LxnKE9WSzPUDWm39ZANKP
         r/EDhoVCE+SGArI72yokPLvzTKmSxdcGKmahp9/2Pm6lqOjhPnYcoV51LOlfsm07Wfhy
         1yVpaphIjeJ2Ckli6CwdbLY9FObXcNry3d3+t2SR3gpEeqld2akI8XCm5VVKCTA2QSnj
         0Qyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K1nHe9B/";
       spf=pass (google.com: domain of 3krebxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kRebXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w9uIiZ0eMIsaowuWU9ykseC3CK79V6//V8WNCNkgQcI=;
        b=klKkIG16HcXQjkJ3aIpc4jfZA250+Xab8WiO67b2T70hTN4k6Ea6P6z/iM8GG72DKt
         1R77WtlDcGdNZvEU1K/BlaCz9WchnKdMqz6YVdjtM8Sfs39/AMymDNji9fkWDCWdqNkV
         hBj2+SJ2PCmytabThgcLpgG2hs2j9Wy/35j+Po2JzobS29cnqU2+AQx/vl8T0rsgV70V
         MJYgnOu1h+gB3CDwYt1e09ktAthtCi7lwSFgH3pZgptmrGrE+2/AjgnTzT7KXALIIm+R
         SUY5Jzi1rZaYrWz2IaaKDvblwG3VQNhdOSPM+9v9EgIZamjl5U31xvaMfSCr6GBYgeID
         I0DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w9uIiZ0eMIsaowuWU9ykseC3CK79V6//V8WNCNkgQcI=;
        b=BTvfgdoWiKh0LuGhMT2LiTaO1ocD/+a2Eya8Q4HY1q/CPl3J8hgYndw7NaUiYdbval
         DOKHgWr/zmI2tS4QK46D0pWY2TEuoLiVNnVJIeOFvbhch06qwkcK3uYtsTkLJF+JbVe/
         rouLbregCSHt50LNPILyO+OXo6Ovyej4T1z6djC0Quc15OUuSgvrdGwBV1Jxs5A+EDPp
         lhdwKtLDtdRwqNxWk8RhZULLRv3ylQT17NptpzPIVJ05/qDBWf+YP45MzcChJvmsmifI
         hLPB9P7/9WIW3Xp7WHMB7Bv6I99NzLKv3u/fqpq7UXsdVFv2unsQI4yN4eH5TMAVYhFy
         +ugg==
X-Gm-Message-State: AOAM533irnZI6e7kN7ClYlaHZQuUMnCoCFAGbHe2t+Em1Ai0O251R9KB
	sQY1pD4SOQAWAOmj0G3BPN0=
X-Google-Smtp-Source: ABdhPJxTKFu1/6lvMvHhYYf+pqQXl1clg7XQIIL6GhlvyIXUm31zdrGqhGyRZShhD+daMusTm2uNZA==
X-Received: by 2002:a05:6512:3485:: with SMTP id v5mr2386393lfr.181.1603999636543;
        Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls2380473lfd.3.gmail; Thu, 29
 Oct 2020 12:27:14 -0700 (PDT)
X-Received: by 2002:a19:5c2:: with SMTP id 185mr2370425lff.15.1603999634050;
        Thu, 29 Oct 2020 12:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999634; cv=none;
        d=google.com; s=arc-20160816;
        b=VJw3dI/KtkNuNRE0R7FAASEBdOVC1UjuE3l59+lDKrhX/BstZC67kNgRZkaBb9EfcI
         L7JQpjBNNc//dZms7xVQYtAVfNbH9b1LDgY8ClGNKy+19hjWcKySBGKyyJ/xByfEfzMO
         IS496QuRjGzodJJkVUA7zEsC08w7WIYDWpcduS3lSGjMgldOIvgw+ECiC9yliR4hb53R
         TLDUl1kWtAMkMrfJMJsp7YhO8WIKlQDhx8ANr5w3PjfrHVU424Hb9/hlfoWhycu1SeI9
         1G7SW/O7i5QubsLqkvi2ptto6DdW/YvaEDO2QP4wm+gHZ2xj2fQuI+gEDqJ148ghVp/l
         ZKdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oA6gmttblv8OmG3VJbCFTsqSwJTzGphkOsRK2ZeD750=;
        b=bsV69tenh7QoJsfsrAma60U3WuU/MKt4pJqMpCGThIoTxFxdrGD3FcJrSf/ZFdfW5Y
         2sa9sIBEvBkUgDmpAsdUKE0zPMOZ1n9ly607Biz8G4Frq0A1XIF/RBNL26d6hFSoxmq8
         DgztI58TUKs4o7XapNs6YCwV0tznfUJzq+sJkfbx+W3o6D7/3/m7FWggMt0aWw7uSKq9
         ExlZOhyTh/GSdYgCUAbwtQGHmOMDSgN3hip0DojTO1USW3fuQ/1sMm0pzyscWhru8+mh
         oRM5W1NfvQycOVcid5krm5Sf+dWJl4XwMLRoozOv/mdP6H6ey0zB484gPKQSZxrgnaxt
         pe2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K1nHe9B/";
       spf=pass (google.com: domain of 3krebxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kRebXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w28si116072lfq.3.2020.10.29.12.27.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3krebxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j13so1699291wrn.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:14 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c92c:: with SMTP id
 h12mr464316wml.134.1603999633473; Thu, 29 Oct 2020 12:27:13 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:48 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <36ab70fef7688f7a43871b82320784a67f8ffb10.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 27/40] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="K1nHe9B/";       spf=pass
 (google.com: domain of 3krebxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kRebXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d5733831ad7..594bad2a3a5e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36ab70fef7688f7a43871b82320784a67f8ffb10.1603999489.git.andreyknvl%40google.com.
