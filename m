Return-Path: <kasan-dev+bncBDZJXP7F6YLRBKXL5OSAMGQEIPY6NZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 072C973FE95
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 16:43:56 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2b1d8fa45a6sf38531311fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 07:43:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687877035; cv=pass;
        d=google.com; s=arc-20160816;
        b=pihUsUGTRctpSsdj/5J9kvnLBsTYY1j4EAmtqdp/mOIJFhoBuQOWZ+GQltjYGdnrj8
         ucC6jtlKTIB5uwLaDJtWOEWqdOutDKMBksPa6ccl0xhx8tgKbMYz/q6yzLYsF0dx2wkQ
         Y8WRL7eRMWcgzH3N0jYIrvrCDTOxatwhCecDyt7k4YXQyUbE9ATakLfx60S14gRvKxN3
         MCsPnXWkc1+PqWEK5l2zfRq7BF60/BGpN1yVq1IkFL8RVbDT539CtUpk0hSo3vld1l8r
         c6NwlgT8586SkPCXsqo7oTLjfhWWotaACPAeTOCKdHPQ8EaL/vJac9VXydmZZAnlYUCK
         HicQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rBH7EUTgPLQYp0g779o7wf37tBD7ZGl4+MHG1EHmDhk=;
        b=u0mqNzLnXI+yAs/gVSe/PwRHVdApYoCIUNhcRv6WBFoDPfJMpeUqSEXHIy9eAguXkS
         4H0SJXkZoIeVo7wfozAU+ZesuLEbVyjGRxo7FqVAKVq2qL2K5w32Bmrfql9X8LjYZEON
         tPJQEjkBJMcslogeFqO52Tl2DBYTVr7O6yZd0PFpDLva5VbBrWjDjxlos+KASK/akkhw
         0SCN6nmWfPOApSAYO2IJ4OpksX+37AOr9g4+Ks/o2MYRc+6VTXbOzwdjmsup0T5v3S/E
         jYcHgS7seP3iw+Gm0AetAPU5Rhtys72WX1PuMb+EHuiAzEW2zIHrHwRV71Vzv0ZpUH1k
         gufg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=YFRO9acw;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687877035; x=1690469035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rBH7EUTgPLQYp0g779o7wf37tBD7ZGl4+MHG1EHmDhk=;
        b=mW3/W7UB1dUdQZT4Lx33//YXe/ZrdFIlUS3zwBFSnoZskC16OvMYcnttvgNJKcAuNA
         MaiJ+cEI6UNYaeRqjM/ad9quD/ZaI287GQCe84zluGk13HCU/7pSvd9V20CtXV5BsTNW
         F5KCFaX12rFBqqyc3V7pQ1Qpw8iBvCfmHEAmTbQ/7W3B2wd/194cDRw1ccEGB7yaTuyU
         bP2aKrThaPZ7r7b7wnDP3y8gvBhlFXI3l/w/iKvjIR78c+2ktYK+EV8kCWogbZCoP1Zb
         edSI7+SMPci/u9xQBNctyyOiq3Su97EHcgqNf9tvr7SgZg2X5bPqr3ovC2L6aQ9ZjaVs
         5r5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687877035; x=1690469035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rBH7EUTgPLQYp0g779o7wf37tBD7ZGl4+MHG1EHmDhk=;
        b=EEn3qvAD2OxLwG/nVb6nATalOmVzypHirB2V7naEgX5oKw44nBydQeB3HSs1ck+Tfq
         f4P3nI66G+tbfa4bvyPNiWI3pRJCQ9FmGk/zRtnkaL/sP43kgOcSQ923WUFPgWczZjf6
         IlhgqKqc9ZzqesFYOD6VTVR+TIX6oVtCC6KH2bwmdwC4gMESiriFgWZzeVbMGdhVwoU/
         Wautoi9wpmq+JJ76jtsrBI0PEjFP1u634VTtyb7TQldLCSaHDWvR+T2SolLAU/QHDotv
         GhO7n12GDHp4Z2oN8P8qYxXuFVxn9G1790fXbh+tgbXbW9sBxkT3bCDEweKWg3hQG0Is
         m75Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxrlMFulcXFGlak4GTfdZYIFyfgYerjHBgvcXw6NZvQc6Xt6xLx
	ni9rK6yDQ1ywVktCG3BL1zQ=
X-Google-Smtp-Source: ACHHUZ4RgeUqdQF1qhYwZMIyQ8k3TRmHidAyKyPfwQcH8BkuieMuOuqdySNgiFqAJf2Jd/aAJH9WuQ==
X-Received: by 2002:a19:6418:0:b0:4f9:571d:c50e with SMTP id y24-20020a196418000000b004f9571dc50emr11966249lfb.36.1687877034517;
        Tue, 27 Jun 2023 07:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:608:b0:4f7:68dc:ff5d with SMTP id
 b8-20020a056512060800b004f768dcff5dls2139734lfe.1.-pod-prod-08-eu; Tue, 27
 Jun 2023 07:43:52 -0700 (PDT)
X-Received: by 2002:a05:6512:3d02:b0:4fb:7392:c72c with SMTP id d2-20020a0565123d0200b004fb7392c72cmr5450190lfv.57.1687877032875;
        Tue, 27 Jun 2023 07:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687877032; cv=none;
        d=google.com; s=arc-20160816;
        b=0p6DyPnHthcuuXuuYKZdTVi8yBLPI6ShBvUwpOf20/r00oOBiWvN0TICv3znQqWDWU
         NHCz6SifSYWcgJkQeWLAGfSj37F8jkn4xNaXLnueQwR+t5/7HnM1RVSg3m/3L645zvrR
         gnCNLX95UmK3NJxpzauAeRhQVZ8B0N8Xs5XztclwrWA5mBDZip1P8cXUoSiCW1GKSPjx
         0OiCNJQfbjKGpvNVcF/ZHu8yzB8QKUoYJ6ixyn4ZO6TUa4PsNKfDZOV+eV59g45Em1an
         HO0pcGoAaegRvhZHdmNBPxjbRy0RXfWikUFEQuMvrt586ThpPEUi3t50Ea4DM+VV9hjN
         dMrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tzdHyO2WkZ+/4hPd1oFud1vh1gFsmlhbwd5pOc3CStU=;
        fh=0KXxUBdGdTZUREAi7vY5lmM/NYX8UoMHfo6Q4BbR6pg=;
        b=BTrlpir9OOZsib53FONcQQGiBVJLez2+UM/BDYfO2rv6DadD5apNGbvbBtoxM/rA16
         sa+m4n7Zu6KILeP5U90uZ2RzIMxhK1OiDhiBx/6uiemK596946qW4gggYSNKNDS6jOKm
         oJEK/Kf8kIN17jQxLyUVStwySgfMwGag5PcHigq+lPc5NphGH3rNCBaNWpPZlG0r+gT3
         +1reGJw2+2U/rCNtAhpWTJoobu6Z78hvcl+3OTEnrOsHcmHufURbV4n5ZKDiCnudeq4n
         Ize06Zasm1SQPqinuEg/5emLHZvN7fMJLWdredLazEl7dtfNVzW5if0q2o54BgjtReID
         6C6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=YFRO9acw;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail2-relais-roc.national.inria.fr (mail2-relais-roc.national.inria.fr. [192.134.164.83])
        by gmr-mx.google.com with ESMTPS id bp21-20020a056512159500b004fb8167d7desi154510lfb.4.2023.06.27.07.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Jun 2023 07:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) client-ip=192.134.164.83;
X-IronPort-AV: E=Sophos;i="6.01,162,1684792800"; 
   d="scan'208";a="114936340"
Received: from i80.paris.inria.fr (HELO i80.paris.inria.fr.) ([128.93.90.48])
  by mail2-relais-roc.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Jun 2023 16:43:52 +0200
From: Julia Lawall <Julia.Lawall@inria.fr>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kernel-janitors@vger.kernel.org,
	keescook@chromium.org,
	christophe.jaillet@wanadoo.fr,
	kuba@kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 17/24] kcov: use vmalloc_array and vcalloc
Date: Tue, 27 Jun 2023 16:43:32 +0200
Message-Id: <20230627144339.144478-18-Julia.Lawall@inria.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230627144339.144478-1-Julia.Lawall@inria.fr>
References: <20230627144339.144478-1-Julia.Lawall@inria.fr>
MIME-Version: 1.0
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=YFRO9acw;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted
 sender) smtp.mailfrom=Julia.Lawall@inria.fr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=inria.fr
Content-Type: text/plain; charset="UTF-8"
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

Use vmalloc_array and vcalloc to protect against
multiplication overflows.

The changes were done using the following Coccinelle
semantic patch:

// <smpl>
@initialize:ocaml@
@@

let rename alloc =
  match alloc with
    "vmalloc" -> "vmalloc_array"
  | "vzalloc" -> "vcalloc"
  | _ -> failwith "unknown"

@@
    size_t e1,e2;
    constant C1, C2;
    expression E1, E2, COUNT, x1, x2, x3;
    typedef u8;
    typedef __u8;
    type t = {u8,__u8,char,unsigned char};
    identifier alloc = {vmalloc,vzalloc};
    fresh identifier realloc = script:ocaml(alloc) { rename alloc };
@@

(
      alloc(x1*x2*x3)
|
      alloc(C1 * C2)
|
      alloc((sizeof(t)) * (COUNT), ...)
|
-     alloc((e1) * (e2))
+     realloc(e1, e2)
|
-     alloc((e1) * (COUNT))
+     realloc(COUNT, e1)
|
-     alloc((E1) * (E2))
+     realloc(E1, E2)
)
// </smpl>

Signed-off-by: Julia Lawall <Julia.Lawall@inria.fr>

---
v2: Use vmalloc_array and vcalloc instead of array_size.
This also leaves a multiplication of a constant by a sizeof
as is.  Two patches are thus dropped from the series.

 kernel/kcov.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff -u -p a/kernel/kcov.c b/kernel/kcov.c
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -901,7 +901,7 @@ void kcov_remote_start(u64 handle)
 	/* Can only happen when in_task(). */
 	if (!area) {
 		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
-		area = vmalloc(size * sizeof(unsigned long));
+		area = vmalloc_array(size, sizeof(unsigned long));
 		if (!area) {
 			kcov_put(kcov);
 			return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230627144339.144478-18-Julia.Lawall%40inria.fr.
