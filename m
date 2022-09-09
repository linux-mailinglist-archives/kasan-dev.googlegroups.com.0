Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEW35OMAMGQEPBMO7IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF6B5B3052
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 09:38:59 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id o22-20020a2e90d6000000b0026b8a746a9dsf206681ljg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 00:38:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662709138; cv=pass;
        d=google.com; s=arc-20160816;
        b=k9CDDGdETd2JmDuyjQVQrMLaFFgrXzNKVI+0jWst0Eef7DN5pHAkiGN7FEL/FsCYGF
         nK7VPmCMZUuDw67x3lOREihcpahEAKmI25yD6qDivg4CgZccXkpLbfLy2MHK0tzRN28/
         6T5dq1vkc1eN2Wfrxt6GDY9FuX/lwu+rDwgsJS4p9G3qb4QMxuKca9jyoOrA0yWzOnZf
         iNWOBkFYxoj2EoP5Sti1RJwvYqoGK4epyhBpfsYY75m0IcxcjSRGenCxqd04y1g66qF/
         uB7FY1PXIHvjpauei9Ih4KooYIjhcfIA7FZEhgeUttXkTRyAYA6cU53iRVcQacQa0fc/
         R0+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5RnpADQRDEcW121I302Nmcx9fzMynb68g5wxGNnn130=;
        b=KAENNFwH4WxU37EzpempK6zuhZADr3GF6NBrjHx1JHyT38XnVu+PP48fgKcAa6ivKL
         PSRUXPesUTiX6T3i+7FpqOoeTordQCgtoLMKampKxBgKjjR5Kyt1uQHviWAAFB/6Tk2W
         yID3QnXCkteqBJg0JxsgtvAbpD9Q+Aqy9u7wpVVNuSND7Qa/m7aE+lptD9yfLO8yWuag
         SsXenupoiFQgl/xnxhpaQjvCWw2yUwj6fyUmJEmWBI0iV47t5Gz7jSM4GRrJjYB0cNd2
         Y+v+2aK/ty/YABc6tCqrKGFEPyJFn2e8mknan6O1qUl2BxYaWtuN4PUc2Jh+rlvF5kaj
         mJsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ktFLEBNo;
       spf=pass (google.com: domain of 3ko0aywukcfubisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kO0aYwUKCfUbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=5RnpADQRDEcW121I302Nmcx9fzMynb68g5wxGNnn130=;
        b=jCGZB7TlMOjx/VILN9jsDBNMyVg1TVnYZ35k+0mRQY0KUV4C+Hi9UtYKCyAdaUvLLc
         x9ly9Oal0EiUkgQIJPEgj/Q72zJKjt61IZbY83+Td3n/sZOMYaijDMWOv1FtDIHB1IeS
         sR7dvbVJDNkOLtVm9UKeitNG2+JsAT/sQy4CNWLX7Bm2ttBETXJ3swudhKjbo3U8a+MC
         IO9NxYA78COcDQkYrYOLlrJfuO4TFQhOMrCTF83sRHuOAnMpsRzaLypHsNNsB6huSSxH
         F6TVmqh+A2r/KYMRbxUfPElc3QIafKCTrwManeIWLJYQzMaD9cKIlcYjGnH+sNaUjttI
         70bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=5RnpADQRDEcW121I302Nmcx9fzMynb68g5wxGNnn130=;
        b=lG6qci6FjsidW0+2Z1+ZJ2g7utN2w8DOD58ieFzuaPV6vzfxl0SzcgUUsIZwdqA5Ex
         pE10u21OmVHHZYC7ajBCN3+aitqtsl8R4ZQviHAclMYi8vFLCQrhNj62/JX0lek5eRHS
         gkW3Rhwx8qzgasCMazxSkTvaFvCCeYTdcttil2ahm/WXlEc6WFyzDt4ebNlXvRPPzn0B
         maUlV3t3wXoNsWrvBBk9OOtUoKrtGsHZxOOCjJQkOLdgcYQXO1/FGC8HGTy4sYYZ9fsB
         kw7HdAKMkLb//FUJPjBlmvTj5qA2R4CyVW+erJqxnbIR2dy+SvZt1xfgCzOVC9PH5b6y
         9EWA==
X-Gm-Message-State: ACgBeo0dlHJI3roKBoaIW6/2tvYye+35HglSR5L8wQF2skOl1eGI+eqI
	m55Sltuz9h6XcB+AREFX8Ls=
X-Google-Smtp-Source: AA6agR7W11NW9uY7yPuVGcKYq9uYq++UV14E3GqaS92fwSeX3Co1W+b/webslAC1HEsC3t/hTnjx+g==
X-Received: by 2002:a05:6512:ad1:b0:498:f052:3a18 with SMTP id n17-20020a0565120ad100b00498f0523a18mr1943774lfu.348.1662709138807;
        Fri, 09 Sep 2022 00:38:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:210e:b0:48b:2227:7787 with SMTP id
 q14-20020a056512210e00b0048b22277787ls2700808lfr.3.-pod-prod-gmail; Fri, 09
 Sep 2022 00:38:57 -0700 (PDT)
X-Received: by 2002:a05:6512:3c8d:b0:48a:f74a:67b6 with SMTP id h13-20020a0565123c8d00b0048af74a67b6mr4561674lfv.231.1662709137394;
        Fri, 09 Sep 2022 00:38:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662709137; cv=none;
        d=google.com; s=arc-20160816;
        b=YGWpGavV6WPYaEvPZoBoNqP8P/MTJlyOGCf7ln28N/N1zFPszZGcyTHiyTAeXoDP0Y
         aQKgAdLQqOnoVP1yH4kGxLkRbxL1ryKxYiGE+5zHKChYOYoFkaIHPl+3MM89mEgpXQZO
         jhz55mb2g7GK4bVf9dwvwQ+GxgpTHegBEtzQ+itFEw+kHPAlmPZouxWl6pAzLL5LYXQ3
         NzliKWqMM3NRFadlsqi1KzhXVCqTZs7GAhwtb/KrxwmJGpvzMcd2Ud5NuQy7bSyxIyvZ
         NkNNxexyw1YY7tpKd0laZq9Ts2ephruMNNjARC/D4LPoyh+h9PlU0xdFD3W8aB0xpjCY
         HKSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Sukv368ybnyGEDYWzkXqyAnNVv6jo8OLy5FNfbPUdMM=;
        b=vriNXHBdlrdhf64Zcy4Lk2FPTLeTn75iq92YeCruJ+eqP0eCO/FYvPH/jAbjeixyv+
         HduTQM+eqz4Cg4IuqfyW+YVoubU33/BbqwZLSBrCED2R4uBE7r0PBG2CYM4DCs2Jabfm
         VNMqbvSLibApVaX27eRrfjjx/TmnNOAl/YTE3zgImFzMk3Sc24YcLZr2Pp5TXnxRV5SM
         mQzzOUTqcFrLaSUFgJP9svr8WaJj4fYBE6k2s/71pS/T1vyqU0tpLTHU8yeGATkg0ggo
         wWA/PVmfiMC6UEIHLzowHBcAJClu9Y5ADyS2lNKas+iUS65bZxhQGKio1M8c2U8wf1Pe
         ML4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ktFLEBNo;
       spf=pass (google.com: domain of 3ko0aywukcfubisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kO0aYwUKCfUbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id q3-20020a056512210300b0049495f5689asi44409lfr.6.2022.09.09.00.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 00:38:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ko0aywukcfubisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gn30-20020a1709070d1e00b0074144af99d1so574517ejc.17
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 00:38:57 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1d1e:ddcd:2020:36c2])
 (user=elver job=sendgmr) by 2002:a05:6402:c8a:b0:44e:81b3:4b7e with SMTP id
 cm10-20020a0564020c8a00b0044e81b34b7emr10294408edb.181.1662709136924; Fri, 09
 Sep 2022 00:38:56 -0700 (PDT)
Date: Fri,  9 Sep 2022 09:38:40 +0200
In-Reply-To: <20220909073840.45349-1-elver@google.com>
Mime-Version: 1.0
References: <20220909073840.45349-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220909073840.45349-3-elver@google.com>
Subject: [PATCH v2 3/3] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ktFLEBNo;       spf=pass
 (google.com: domain of 3ko0aywukcfubisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kO0aYwUKCfUbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
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

Adds KCSAN's volatile instrumentation to objtool's uaccess whitelist.

Recent kernel change have shown that this was missing from the uaccess
whitelist (since the first upstreamed version of KCSAN):

  mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Fix commit message.
---
 tools/objtool/check.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e55fdf952a3a..67afdce3421f 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -999,6 +999,16 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_read_write4",
 	"__tsan_read_write8",
 	"__tsan_read_write16",
+	"__tsan_volatile_read1",
+	"__tsan_volatile_read2",
+	"__tsan_volatile_read4",
+	"__tsan_volatile_read8",
+	"__tsan_volatile_read16",
+	"__tsan_volatile_write1",
+	"__tsan_volatile_write2",
+	"__tsan_volatile_write4",
+	"__tsan_volatile_write8",
+	"__tsan_volatile_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220909073840.45349-3-elver%40google.com.
