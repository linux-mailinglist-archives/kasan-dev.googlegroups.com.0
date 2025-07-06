Return-Path: <kasan-dev+bncBAABB2XIVLBQMGQETAU54XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D255AFA6E7
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:48 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-86463467dddsf243795439f.3
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823466; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sm56Q15s5V7E0dYCW1jeEVnt13vEZYZxr1B2C3ACHUU8IwN9qdRSNjwGGdQ0OangG7
         gR8U22HQKQcQNHjUSAfb0JjZPA8BxeL2Y33R2q4GlKKbk7DHR7oHe7vrnhUnyYIRKf9+
         ZTFvEMdz85PZVybjJd4unOSABlrbvYq/bPs7OBVI32HpZaISgngbndBmbhhveLdRIRFh
         /7ReaxE7oDIKGbJZuHMWrSue6wtovumjXZOFxZu6P8ADxgCrg0L8voEAUYDNR1Wx7p97
         PiriXmrmWfi/FeoM7cugIZvTaMmSWAzgrmtZFL8zXfvPM0+mgJsHvGIU+LKBs75J+0DR
         GLaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oAUO8ljsTcsApYyeOCSyCQAxYfnn4cJbA4kG+rtfeGM=;
        fh=HoOEtWf+53XkZFTXFh3uC/Jt5wzYQZx0MZwNHK7wky0=;
        b=Zf9jOD78L4oU227z15h1zYy3PH8OaclOENAoLUziXlvFZ5QiM4JM/1ihFh/mBwjpwq
         fQEoL1RcQ23uPqaKDOnHjahTgdA+HAlgLprjYJfBZ8CApGBqsZqi8a4mTl1UaNyWlsyp
         4NsAM6h31ELj2KXxdJKEDvFoATtWx5VpeLdTCu8iZbhlbY6x9KDAuRHa6WgGhkkXMgMq
         eRZsx7ja1CYWLTpPvsIdcIvhn5pT7DPDQuA+3+jj2LJNtWV+0VdO3g3ZUEibWKTsuZy7
         XJFDJtLf7djFfRDbjvoirL/CrqoyrAsPt82lNecCEJGyUamLRtigFbw9RPCChjf7eQOx
         z1yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=orXVAk+F;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823466; x=1752428266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oAUO8ljsTcsApYyeOCSyCQAxYfnn4cJbA4kG+rtfeGM=;
        b=CHOvhM2JVAedA0vNwm0ue/C8eOkFFAE86DGsZ+9ILycanMo15NM3c1hwv+gZgxXH2X
         Ulxlb+RjygAxO1NP8Df4O4T9Yvon6zOfEiEjyY31+3E9ngcIgMH8fATazRIX6rxgZzBd
         /EqndfMH70imc65hdIuy1Yk0fGtYkyjnFEcnivleMY+fK7uY4wQDxZEoQ0V4SNsXEeiy
         c4+8ZJNl5CwvSUGT3E5iBxM6VCTb4wvG23aybfwgB4MJ4LLisOrnnVO3BgRV0sqtEIaw
         h1LUeY7SY6ImS26qC/7+LcCp6h4M+t9l2ixcaJP/bV196GoJXQZJwV3pWkmEQhClLLV9
         4zwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823466; x=1752428266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oAUO8ljsTcsApYyeOCSyCQAxYfnn4cJbA4kG+rtfeGM=;
        b=aYiYpUnT4cmU9Jjv89serTTuFYilcXq4JDZhDOU4wPn9Ttyu0ItAh/8ltBh8ZhrYrY
         22JjulzC0XvMh5Zezgceaxvv9jlRgyENYsSuoLMN3q77IT/2ITR1lFpXQFxGfpExhhcw
         8YQNFBrkCgMg3NWErOIFCSryOZUO1wjuLTMHh9QlTsQ664ExHVWltBo5E+FDxbcyrvsS
         jqHTUy+S9pO8gVUfPD58MNLueFv58OBDAc1dJjSNaNwq1HeJbmJDvF/PGFs0WvQZvvzL
         HcOKlUKz1krlt40flvIhEVQ06gG/wTSTq42aWi4KNYAsCzE67IVsAHyzzP7Fe8CZsyA4
         5dog==
X-Forwarded-Encrypted: i=2; AJvYcCVIKJbmFREV1uj9BZmOynGJqHWgMOU/+/HhTZeOvIsVoaK4ihe5bGpvw6B+ZUR1H+H+PkG+NA==@lfdr.de
X-Gm-Message-State: AOJu0YyL2ALLHUcHC2JyKz5l8HCfK+/y18bk3mhIFoQHo4PEKE3vHc5t
	mt40m8A4bqcvJkSNQlXW+PVQ7/+RIjyQwB1C7muA8M7wu1M/J7LancBJ
X-Google-Smtp-Source: AGHT+IFtYh1+sCzGpP1GSFTDyimDCh2ntXCWEe8jS6ERxxQ6BngcRuHoP0nGjITKs78STIvGIFuqhg==
X-Received: by 2002:a05:6e02:3f0c:b0:3df:306f:3b25 with SMTP id e9e14a558f8ab-3e1371d0bd2mr82030585ab.16.1751823466578;
        Sun, 06 Jul 2025 10:37:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxbai8gawoRlEjUGTZc/d+oEXIZWfrecBmhvh96AttCw==
Received: by 2002:a05:6e02:5e86:b0:3dd:bf83:da96 with SMTP id
 e9e14a558f8ab-3e1391d9516ls12914045ab.2.-pod-prod-09-us; Sun, 06 Jul 2025
 10:37:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1z02QcELFbG7j8jNJQ2u8lo2j328GFLYvcMNMTzfBLtD8Ln9DLqtqiXlTWl9YXVXr1aF19JC6luc=@googlegroups.com
X-Received: by 2002:a05:6602:2d8a:b0:873:1ad3:e353 with SMTP id ca18e2360f4ac-876e49044ebmr754280039f.9.1751823465808;
        Sun, 06 Jul 2025 10:37:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823465; cv=none;
        d=google.com; s=arc-20240605;
        b=KY90rzNu98MjYGn9o5TgLqKvyd874jV+OVP7u94SsuVqEp+6WoyJIwXglZX3isQ224
         3PojKr8ND/a6CR8o22hPVJuRxB9fHJcvVfqg5kg10LzkMiF9e2u6DBztRHaBvaAJuyxc
         uVCtrV8Xv/cADF6Q32u0Ih65SGQRUkcO74SET4VybdccX0BYl5aQE9hvt85kURTyy963
         dNAjDmnaSDm+iA4JavmX7Ogb5UNCzJ1MTJOn+XyywnYm5XmLoAP9n5OzNMLcj84UiZq0
         4g/vOBetkuCcxuAQaTAImdWx15Y1HG10i9JGWsTgXOEyEZfSJJAd9YsIiM4WQfX5u/jp
         2OiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=39KAwZRzDNDC6hWvgyKPYwRRM/G8G1bD8GxjYQKK8io=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=aCEXAKJRJXKawM/JFYQ+SFQhdv13k52Tni+LHgkp1bZ8Jb6rmNQeqOornDf2RBAn2P
         07OUKoiLxsYxnfMXeoC8TfzDIDOqJLLSxAUfnXmojzymC/BAakUCfd/INGqO5BtteL0a
         bkgcS6AADIC9/CHTZB2rNFpnqYxzOyU4RfumiNkPwt1suqIvDSXTQp9Mkyaq/YDBXUSn
         RFjgXYb5f9jm/E1A+CeZr/JKDK77Bu0hP03kOVqn416Fuk2BiRkwn5s85blt7b73i8o6
         V3LzjQUr8Cu2f6h2Rm5JVimMnAIBYjwW1hAELVnIVDVxXFcc5a8BZebpW6xQgItcTEYq
         WauQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=orXVAk+F;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-503b5988a0esi170312173.1.2025.07.06.10.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0B1B545DEE;
	Sun,  6 Jul 2025 17:37:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8C44C4CEF2;
	Sun,  6 Jul 2025 17:37:43 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:42 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v2 5/5] mm: Fix benign off-by-one bugs
Message-ID: <08cfdd2bf77911ca6ce3c0b6c310daea77eb307a.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=orXVAk+F;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
doesn't write more than $2 bytes including the null byte, so trying to
pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
the situation isn't different: seprintf() will stop writing *before*
'end' --that is, at most the terminating null byte will be written at
'end-1'--.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 4 ++--
 mm/kmsan/kmsan_test.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index ff734c514c03..f02c3e23638a 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expect[0];
-	end = &expect[0][sizeof(expect[0]) - 1];
+	end = ENDOF(expect[0]);
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
@@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access information */
 	cur = expect[1];
-	end = &expect[1][sizeof(expect[1]) - 1];
+	end = ENDOF(expect[1]);
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index a062a46b2d24..882500807db8 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expected_header;
-	end = &expected_header[sizeof(expected_header) - 1];
+	end = ENDOF(expected_header);
 
 	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/08cfdd2bf77911ca6ce3c0b6c310daea77eb307a.1751823326.git.alx%40kernel.org.
