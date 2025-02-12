Return-Path: <kasan-dev+bncBDDL3KWR4EBRBB4VWO6QMGQEWJKM27I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C696EA32B6D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:21:28 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6e442b79dd1sf125269566d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 08:21:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739377287; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z2H7r61nMVtdhJ4TUUY8xVtJL9AJbyXpqCH+byiRkKWqK4DaNj2c7BreOHTGlYnvZc
         b8J82jSorBMF8BiOlglzSZdlV94FAErIaYWUqFkKsUacYBkOyE3vNGH4muDOLcLa9+Vp
         Z+ET+JILK5TBYNMChzghcNcOk3bwKGpPPJn6Ofj8QFKadB9SOitCAc7ISyKUeQp8/+Fh
         wdhrjLbQRZHfQJoGgxhFOH0dkyRh4OPMetBWpK4EqMQDffto3N1JxxbD9uM+RTMKCq70
         tNZJEDAH6lFzRyOVlk7JR8Dopd6mXlkSmJPdQHqa44LmCx1ZdLoAUHZ1KPTZb/fGRmU5
         dkow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7QpxDJrC+HmTbXcewx9Th2mxdT2gbH81uQ2aPXRPeuM=;
        fh=u6rYJh1PLsHlCPKJYZrmiXgP4kgZ3QEWuhFswgSc/2s=;
        b=Na5DcEjj9Xu6WkQYm2hdTdoWDYKizLc1s8qcK79X1pQTCshMXmRyQmbmJrDZiDKGRt
         C6dmKZnQhJA3/VD0sDk5OJaaiO5QVv3Hz7LTQZJ7jvn5J/PQf5TkqCucybasAaZxVXMM
         kj70/OF2nxWWGzUy31SlDK2r6j64iEmqAKMvQOISc8iVYohixiznJwNmIhIfgQlHWHi6
         s88/5EaNeADexhjloLZchQFp5eUEa7iWx0jC1CGGFctkyox4I3M85dLoVwASJ1LyOQrr
         E19jUaHlYn2kstJfrU+M9tpfnjgd0/kcIbI0eRM+sRWQ+5JI0W+pLjamcSNn4JI3LX1F
         sWzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739377287; x=1739982087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7QpxDJrC+HmTbXcewx9Th2mxdT2gbH81uQ2aPXRPeuM=;
        b=ASfK1ehuM5uJL0CmqUDDsgJGiXhq5ZjGH4oTmts4fjHydycdny8px1RFtLQEGFJaye
         6jYymBYoZXuc9FfLjeq1NyyuluVS1Ldu1UC630LX/nabGZsLvpJ3N6XoSYTev1WpuhtC
         5W0P5zs04kGFc+mmJJGKsS+4J0m9RoYmkS4X60PQ6wxvqYZuiydMBmuey/I8xNsz2HaF
         UyICE/rFpuWESQVpPHTJ1P+Jd3wP2JEduTdoZkve3PyvOrax9VbrxAUfNsfGOOawXdVk
         VJ1DJajE57T+92xCId6eHHkeeyfpGamEhPLrJwtpeHd2+Db/jS+A8/bOGGGn3Emu7mLm
         GsvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739377287; x=1739982087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7QpxDJrC+HmTbXcewx9Th2mxdT2gbH81uQ2aPXRPeuM=;
        b=NTx2usriWSAsN7uFMTATL2Bws/oD6y4vGJI681sYp1x0pKq8AP4gXtYcX5+Br+7gte
         iUhjZripBqzUOZXGSYozd8/4c6Y89DC8fjbYiHzSNL9GBZf15lw0e3vOBDy6UImte4Di
         RvlmEaA/uk3hQD9ijb7ywnGoo0+xvGpw2KBDny9kd7+LubBS2ikTUgSRe8O7r6AR7Onr
         01GuczEthO1VwflTE3yhXIVNSPvTOUFGPEHuefVJnGHzKWZUrilzirDSdwTJvHgVaFAx
         bGphcLY02uBqyFMYrWuP6mJegjOc+PRTBRD7PgJDYbDO1EHivDrs/i0EyTrDjvNS9HgZ
         3oSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVztUr5XVUn9S1HfLcx9OMdI/NPDra4XP5IFS7rvioZxgKrkzeY7Oqj6BQhyRBH6w9DeLH5ww==@lfdr.de
X-Gm-Message-State: AOJu0Yx0+viqpUSYbuZvysUoR1+WRlLtgUZBwMCdwp42RnuojaEXPfxR
	Cm3zaegupuHjaVUhL3Rh1aVuusOgYbzHdmqYFTUVNo0v/e/9UmWF
X-Google-Smtp-Source: AGHT+IEoDIBkzkgfp1Opmc+8GBTS6cywCbw8JKuyDme1b0Dqi6A3Rf82T1bPUgRtxj+wj0iwA9Ckbg==
X-Received: by 2002:ad4:4ee3:0:b0:6d8:a84b:b50d with SMTP id 6a1803df08f44-6e46f8c9b0fmr51366346d6.33.1739377287594;
        Wed, 12 Feb 2025 08:21:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5504:0:b0:6e4:4503:bac4 with SMTP id 6a1803df08f44-6e65c215cb3ls58096d6.0.-pod-prod-01-us;
 Wed, 12 Feb 2025 08:21:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrIJD5vVvsFGSl5QcbWiSW1Ju4at4UI77iuWzJ4qJ+yhLFctnTbVHqcpzc2ZOc3eQlvYF2K5nn4/E=@googlegroups.com
X-Received: by 2002:a05:6102:4427:b0:4b2:9eeb:518f with SMTP id ada2fe7eead31-4bbf5528661mr2807151137.10.1739377286656;
        Wed, 12 Feb 2025 08:21:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739377286; cv=none;
        d=google.com; s=arc-20240605;
        b=Qbp/KtJlSLnTYh4scfUZBz75TFHkiPYPoidTTrzRQZLlK8grB74ONRP/raIstv6oED
         8FFUOgsQyHToQGA8YcT9FDV6d81vXgdEgG6I6Dr8YZ//6iMHpFQvTHJD45G8FlKcx68E
         r9gq/PsihhWDbhJeg9T7EPSm1OpqL/8FqcKk4FIwMq8JwyfBvBGpR2xHiTkyLKvYeJ7x
         tI9fs6R9OWacAYsc053BErkuq25vxZCqF75FTiRHonr6k5rAf+P7tZohZp31grrbxLV6
         fuuMDrKvOnICDeDgCwU6zPwH6f6J8X3s/ugCCOc8lmr3ykzRQt/rm/1hQhCcVkb+UixO
         c9kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=TQHyxxf7U+Q7ArPF2wvkaxK+HZ9Xg/0EjkAQ4iTH/Mw=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=X7EF6R4VM0nuXmXd3aS0mcv4X9kECWghxjsuLZuYVfH/JGo5enEeneyuB6YLmj28gv
         XJOvMZp6wpTth8XPlIXLEdRw0qrJi08A6nmusqDl9grgGG1QayCNPrYW52zY6G0QEVuV
         SgpOh/2NrhKokQidPY4vgiRk4nuDNFOTIq3lAtXvJ9nssHk+u9EMBklH1oe3OoyyqkMw
         7C3Cd7cHLGo5+H6NwUlnK/Gk+hP5owqbF2Tv/7fWE2TpsA1m9X09jYhbQCUxKizdmXpt
         g0mlhu7XIFr5khzEGrC6z5uzLApiodbQJFGU22WHU/vBg5L8unUG7RNdzqcK7T3f0LZ0
         lQCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4bbc51e35ddsi343345137.0.2025.02.12.08.21.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 08:21:26 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id CFDD8A40C23;
	Wed, 12 Feb 2025 16:19:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DC65FC4CEDF;
	Wed, 12 Feb 2025 16:21:20 +0000 (UTC)
Date: Wed, 12 Feb 2025 16:21:18 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
Message-ID: <Z6zKfvxKnRlyNzkX@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-3-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241209024257.3618492-3-tongtiangen@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

(catching up with old threads)

On Mon, Dec 09, 2024 at 10:42:54AM +0800, Tong Tiangen wrote:
> For the arm64 kernel, when it processes hardware memory errors for
> synchronize notifications(do_sea()), if the errors is consumed within the
> kernel, the current processing is panic. However, it is not optimal.
> 
> Take copy_from/to_user for example, If ld* triggers a memory error, even in
> kernel mode, only the associated process is affected. Killing the user
> process and isolating the corrupt page is a better choice.

I agree that killing the user process and isolating the page is a better
choice but I don't see how the latter happens after this patch. Which
page would be isolated?

> Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
> that can recover from memory errors triggered by access to kernel memory,
> and this fixup type is used in __arch_copy_to_user(), This make the regular
> copy_to_user() will handle kernel memory errors.

Is the assumption that the error on accessing kernel memory is
transient? There's no way to isolate the kernel page and also no point
in isolating the destination page either.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z6zKfvxKnRlyNzkX%40arm.com.
