Return-Path: <kasan-dev+bncBDAOJ6534YNBBIEO57BAMGQEOMC2MEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F05BBAE7E1A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:39 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-453804ee4dfsf6517145e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845217; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cyas5u/bq/UgAXkfINrsnsP8Solrn7V74bpCHFidNvsoI4MzIvb9eNsxbWkUr3NCU6
         L4RKuRPACF4HuSf6RV21zVfVTIq1sNqfVUXGkXpKLqFjlUc7N2ZkRCnwIpaPTq45rgWB
         q/oojkRP1bB3KjBY1zWvmIUJLi31t0cDwxYqjStnIpPGiP88nkXCAENYAT7cJ6lq29RC
         jrtEl3S4tALiMtkAobj1iYwUJ8yYJf0msVThI+SfkI25KBXBIhgW+3dKnR/ASVVUYFm5
         AWJeBtiRy4Hqe4t9U8Id4H6+ABs7uawnZFXi5ibFklTfty3gnszv1P0N12aJmt+8qjD0
         fHqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cBHmbE01W6N7V421ZH+m+gTObhw2l4CjBCXUL71zkmg=;
        fh=M1MEKSMWKGPGSawZtgw+ofqGGqe8gE74sSd/HNCgTl0=;
        b=SUekG5OifBTqPzVV56qin33c6pOduRqyGssKp5uGgMoYvYxDZ1R0HYhPEm3SKZaUtA
         QuCdlgQa6Eu5/IkjQU9cOgFqwJnIYzAFc/xUq6WYBmMleDCTxdnGFGV8LNLNgVCgwMaZ
         xU2GDcIjfjrVm2OBeXBVouqo3IC0ApLMEoHnwsKxuoRKeaKzOk8twc6SESH31/AhHl9x
         xklNwZmWFYgQaKZQkjwVFaCvYeQoh8N7o5cbl2cqO2oLAXs9+P0uWFtOWZcZl2vtM4am
         iRdBKhNZFyFpzLU/cJ9s7dNzDg+ajPmImTanX+rARcW5GQDWMl4JSiaAjwmEqwBsUauJ
         u2HA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lRvt3L8S;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845217; x=1751450017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cBHmbE01W6N7V421ZH+m+gTObhw2l4CjBCXUL71zkmg=;
        b=gUmhuBeIibIe1On+QypcLO92QgVoLs2whex9jXJ2Z7vDILAflhJX0+DxSqqX2D1kn0
         +ogFyB7MoqEDCx3juLa/nP3LoQ2OUi9DcnvdOVhxFRRnXrKGCC325TnMH0GE8gVlwXfk
         pNwQEwcB2t7ddtirZs6Jusq+986p4WfazxvVp2zvpTTmKj/CNaSdk7o1hrLkLwkOY9f7
         3z3G/0/NvNyBJNdozp9K6GcW6D8fThkaCsZQXt9H71hMGgCGAtZW5cyRQhE5/RZVIeu2
         ZMdOD+75qnGcdzihddMc2WEmOSHRSboMVi1hrrE0XvSHRxajjpIkFagl7x8/vxHlBZYH
         z0uw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845217; x=1751450017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cBHmbE01W6N7V421ZH+m+gTObhw2l4CjBCXUL71zkmg=;
        b=hJLAHbcgloNebL9v5TPqxjgXii9m8BXOUA78ymirBFGUpqhvzDzntppsRmIVwXtuWx
         eugghjVI5oSknW+NCUNxI5bfrVJf9WLHDi1iJxRk1jH8rwi4j7gDETTwrskpiZJd/+Jj
         dh1wE+z+yZGxs9dz4rAPvkfsI9CO7RfgSArP0gQLnxR4Z0GJvp5yg5clqFxBM2KOe2gU
         Bysvl0u9IzWNZb6tShR3+8xKxbR/O5Y99aaiznxmT5lLhPFcgN43esazUUkT9hBfKMJQ
         f2af8+fDrSxS6hQmIywZm46+MHw7pb3JNfNwz7MA9VJVHKNHU/BK82xEMuZIInDqqX8q
         +RGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845217; x=1751450017;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cBHmbE01W6N7V421ZH+m+gTObhw2l4CjBCXUL71zkmg=;
        b=b0Ooh/j+d0hjoGY1+f9mxXzMrfAiwORdbzpwEMlESorFZsSyf5GYAm2YWUbTjJFE0t
         bYHDp9U78ORycuiZxtsnKgaOYVdhUE6ekipRJ1sJ91iXhEGY7pUVgiZ/L3QkCHh3DfYU
         n2kmVZ2H2a73M8TpeBtGhiGw0CsFICznsstABdrEHWGyYG6DIHd8hztd93oS2xAgoZGv
         SNNsvTry7Usk6Lr6Oho4fMwfGM//syU2m4pZtvykC0iIUqkbQOVrujp3IakMjyYyChSO
         wOqiZr9HcvIABAYFHNOFKo9VrfXFBv+64UEjVwziPoGstXPzCBapShGeEHJnr0Z5XQBR
         aV5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjVjC3dL9i15PUjekMqphAX9s5eMx8B9hTuCtl1AHHtrAB+d5DVeOjvg0+moaopm+gBDItCA==@lfdr.de
X-Gm-Message-State: AOJu0YzcVWZpDXFcltDC+9sSlRFDENPwq/rZNWLiZzNhRcKjQL15mBtU
	W2IdMeSTATy9gtCy7D3K8J5xl8XVFP8QQpHcaFxCwwzyb5may0NBEik0
X-Google-Smtp-Source: AGHT+IFoTGrmX88RInLKX30JKQgFaQGfPFGp8SdtmPpLz/X/CCNHJ6vx0e789ODQd6TbvtlAwtYWhg==
X-Received: by 2002:a05:600c:34c5:b0:453:6183:c443 with SMTP id 5b1f17b1804b1-45381ae7a71mr22642225e9.5.1750845217025;
        Wed, 25 Jun 2025 02:53:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcVvGvkb58Ps1/miNI7riyVo8YOkGptNuqnB4ETbzfk9w==
Received: by 2002:a05:600c:870f:b0:453:f4b:a664 with SMTP id
 5b1f17b1804b1-4535f0c87c8ls32902685e9.1.-pod-prod-08-eu; Wed, 25 Jun 2025
 02:53:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWt5xzgU1rBiLsECaiNVPjVqj9hbhdujuyV6bSujh8Xvq7xnW5I3WzLKLFk8uFJb2u607sFKaQgbW4=@googlegroups.com
X-Received: by 2002:a05:600c:4ed1:b0:450:cf46:5510 with SMTP id 5b1f17b1804b1-45381b1b782mr22194775e9.29.1750845214633;
        Wed, 25 Jun 2025 02:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845214; cv=none;
        d=google.com; s=arc-20240605;
        b=jcln/xESgQEmezA1B+LjKXm3UQwpo97PRkH0aKi018jIKu5J4t1gc/1YYgAcwQc5YU
         eMczOoxDV+MLcFmHYLnZveZHOX0P7eo3KQrJ2fio8Ih7IEqNw7IzDVEWpXz+8J2mJKx4
         gI5M+fipiaDcKHjwueDJpEeLTTwQ2bcqGFicRpfF0SvavsL81xaeH7vTPFTJzryg7Ili
         DBguPDq4OqrSC8PBoossRKL2/vzKeuK3SAjzA9etAjOVFK76DgH6FnqmpLrD+tAqAqHX
         wL5SCQAhe9a+dq+oQ+ID8sv4uJgItyRClrjuKVpv/90Vjyca2Jt8JPDN7aPPl3kHRgRA
         YbBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BEyx1UFRvpVo+G4N42POvQdsD1hWzSpAcJ0U0Tlc1dQ=;
        fh=Q2KyBJcMMh7n2BhH0AaAHaH7B7hrGpPK6bwxMWyUqWI=;
        b=R9JZPl1KSVUUxwC/w3FZYK3lHpqsTLnw7XbwCcgqRk8vHRGP3z1WjyEoNhtBsb9924
         ESXT/g4UQZQTUN+4JZpohDccBLssP56+UMojJkRFh5Vfqf1pna6gMKihXqmhXo0sJ1Ik
         bbOcmyBNqZo50MGTSHBZ6E/7SY8DoVqcT+MIKWM2joi5UVYXxg6Kh0ge1+gCvKOlePtQ
         E8QLYV3nsA98fR5N9pe2Tmupt0HCL2CfqTNK6dEHEgTotfPt3Rpx+cPzf+LUpBA4mXqN
         bUoQjmm2xYITkWnR05x/TKkuP9Bc15eD1pHYRlwKrq4XEB79gt7z8IAjTVTqs5yBRAfL
         GAQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lRvt3L8S;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453822d256dsi313555e9.0.2025.06.25.02.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-32b553e33e6so54955161fa.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZ/So3A3zYyNSKKRQXVmAPZ8trRA0zNjrQJw+YBuz4UfkxqeyxAmXFT9joq+ovQJXp4jpjC+OhYC0=@googlegroups.com
X-Gm-Gg: ASbGnctEz99o7n7/CPvmGyKPFcqKDJmAMEU+6E4wcPkzAtD2JIqSnTsDYE6W/GTrnN1
	BFEArMf9Npgy+ELjlaYHj3hJm7Iju9cS1fOPfB29itVgDX1BtTG5t0J+hb3odeQiOKbZ13b6jHf
	V8gfv3LC1W1d3z5hy3e4Zu65C65hcUkXnSOVQ8/S/vn/FGSI5qk6H1Ge55rFQuN8JZxmVGEg3FT
	yudJQi+g/KDs3HFXqjBMkbtv2/H63cdLrI6dgJAApJUvbTYyEXjqlw42M2Dh+zgpcOez4r/B0gK
	ZX68TRgxmHCQV828pXkUoebR6e3OHC474G/X1uJ/F8+4PMUINqBFW9t9EnBDqBtqd0Em4IO5YWi
	s64k7IUqWnwtl4DuE5HgT7JJXbdUGfA==
X-Received: by 2002:a05:651c:514:b0:32b:3c94:992d with SMTP id 38308e7fff4ca-32cc65755dbmr8009981fa.28.1750845213516;
        Wed, 25 Jun 2025 02:53:33 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:33 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 8/9] kasan/s390: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:23 +0500
Message-Id: <20250625095224.118679-9-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lRvt3L8S;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which enables the static flag
to mark generic KASAN initialized, otherwise it's an inline stub.
Also prints the banner from the single place.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/s390/kernel/early.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 54cf0923050..da7a13d9ab7 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -65,7 +65,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-9-snovitoll%40gmail.com.
