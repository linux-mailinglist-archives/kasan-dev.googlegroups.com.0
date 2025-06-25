Return-Path: <kasan-dev+bncBDAOJ6534YNBBCEO57BAMGQE2OK6T6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3324AAE7E12
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:27 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b4ef4055fsf36365901fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845193; cv=pass;
        d=google.com; s=arc-20240605;
        b=gQBgapX967WsoYdkKZjIojXgJRHl+dJdUCvKRT+x5yE81fBhpYThb0wInA176zvBat
         MEdprLJ959YFOKIsZLDvE56duH9BtL5zaTinlzQUP6ZqvEak2/ugbOFi4HWMSqqmgfVh
         6Ko6Gg48As2C/ND4v70PEaqszJpgvkfRrgRta3Vf45v1Cg9F7C9SE5ZcNhaLPx2RvnNU
         81vAl7/eJ8kRHPRaG0r1GUfEza33UeMHqyTHLOYi1CVk0yeM4tLaXjDXlp1+MvE++JuK
         ZOE2ZrUhQaDPVS5Rqe6jDgG2NFjPZ7UeX2eW7AhkPEShz7ixIkwlvLBC4Qj1/Gz097fp
         HVpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=iGSs68O9Hs40xkAAj4JUEFQKbMuG+J02Ie3Pwhud8ZU=;
        fh=B9U1M7ohMxyWjmr0rAtj7FQItXC2+B/9KHGZFCllEp4=;
        b=MMOtcuWquvSn6JiiCnNNk5bEmYYJa1SsDhMH6tT0I1FYXxjV2GZILSDH+YuZAgl59z
         5Ro3m2L42XAe90ey28BiEKvQSDe5K0XbNNvIRWbpn7/UFjEbnV0dXVWPzA+x3dtbIAnO
         boL+rK3im6Yc1z0+wqCEJf9n6DCDXmSU8Rlo860BdDxbxNfjowqmvaYUHyqH2rLYOtXA
         +ACCCPeeyTzulUI0uYBJcL+eoaW6OwNiOWkAPkGR0EIzy6p6oobLwHpkib9cmGFlV0J4
         tuINSVq/kZC+W4dWArMnNDyS4z6jOGG4P/Xms/ZYA0lAeobH+GkRUSgf5MMlcNChAZSP
         1ucA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FgnNVOZ1;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845193; x=1751449993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iGSs68O9Hs40xkAAj4JUEFQKbMuG+J02Ie3Pwhud8ZU=;
        b=tsOedDY+woOeFSHFSp60HZ0zH2zdgAs5b0EZgN5U3XRFT/w1w0NeBLzZ7ajJi5vpCB
         r60Nq0gWUZwyuXrc1Oj+3Aq3wOGrZh/doyX/JIeE216uhasXSS70YaDQIef6GK6HJsoS
         EI4TqQkVT96mrNY32a01uxK/D732YHCcsEMLKhwAsPooD5RZVu3Vj4QS6TlDjAaYkWf1
         Xh4BfIqapAQLevpSWm1k3/YbmznJmEyZir7cut4geWzIdHzOXgEmExKNXzu9ZTvG9Aqz
         mi1EqT/adAwR8mdTzD4z1HVYTcZXdh/saluFTzB+3BRxCUGNQQ4O2R06lpIEpwvDnDVH
         odZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845193; x=1751449993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=iGSs68O9Hs40xkAAj4JUEFQKbMuG+J02Ie3Pwhud8ZU=;
        b=A3vwS4+2vxRlfr8ar7eEbUvGsWljShK4RMFpmeQTK0D05BjXubgUiiuBfOCwhhLH/4
         h/l5svuPMosvF4PVBq9ljIafHKPtLYQiEE4m21mBCwuFdZoNvj7VCNwp/VJPLJ4XzCZb
         sNyUN+3Wb1olPLVI7MlaYagqDtmJ9pwOpF/Qh3csNwi2Zql6261f6IsGIRqWzOK6JHNK
         dWxVc72mSz55hKT7IMRLN3elc9+hnjDmqKYHHitC2m3M42MmMYskISHhAUYmyPuROVus
         j50yN7Mcqn+gleLQKF+EnJRtbj9yaR75s7YGFJLb4bwsFEzwYV6uLQRT4gATgn6xfKZf
         BGKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845193; x=1751449993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iGSs68O9Hs40xkAAj4JUEFQKbMuG+J02Ie3Pwhud8ZU=;
        b=tUSiegRwXMJNS8Olo4Glb8rJ3JgZ9d6u+RsKHgrwegD+dCP9ierLnCfdNHwtLbaoAO
         v5785UKMsF/yIr+2VgiwsYnDkFGSh0hRj3BfF/WtOQ/uIordPgVq2UqX0N8znOpCSDR1
         h8I5Xl5n+mXcUhvuIeHoJBJ+fGJ/zAfTqrN0fh9wyB3Km5sUk87MeyeG+esa0/oMl+M3
         51My9ZXhiLkthi4/MDcwTYg0C0W18bRCBNB/aJuQZwbRTbuY3LmpAC/KZZQNatQH+Pqt
         +3XvCPgGxWJhM4ElQH0d+7EEKuloA1pUZ0ORcF4HqA3B1bzWyZAcmD1fkmTaJxW2NMJT
         3siQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXK7azm+7TVrdPsq084IqaBxHfihqV0DCyHPe5Rj8TsQ0UvzTK5Lnw7CkmSY6Zghvy5vADEng==@lfdr.de
X-Gm-Message-State: AOJu0YxeL70qjESA+b9upQFVQQ+r9u/g4hG8rVt7+JCK9Y+c7ee2jORt
	c9SWqcEP73pM+hOStkcMn8IaFlULDIuFa0eM26xf6QSdYBqH66hR+tR3
X-Google-Smtp-Source: AGHT+IGVMneL01qMnK1/0hF9oHmz1ZbF9Emv2gP0nAYQIekZ+rSKd79ipj17tP/8FfRMVyxYraJwGQ==
X-Received: by 2002:ac2:4e08:0:b0:553:390a:e1d3 with SMTP id 2adb3069b0e04-554fde59fe5mr771827e87.48.1750845192591;
        Wed, 25 Jun 2025 02:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdT59LlRfQzE9soydl4pPR6NF5a7MRt0KXHRKWzh++89g==
Received: by 2002:a05:6512:e88:b0:553:298d:ffd8 with SMTP id
 2adb3069b0e04-553db41eec6ls1553360e87.2.-pod-prod-07-eu; Wed, 25 Jun 2025
 02:53:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxwY9XJZGeDlsfj7yfvbSvPzOT14Ea2/1JFqVrymH3f61wNTt84kq21r4o04CfPWMLPKPsx9zVBgQ=@googlegroups.com
X-Received: by 2002:a05:6512:1246:b0:553:aa2f:caa7 with SMTP id 2adb3069b0e04-554fdd1ba73mr690747e87.36.1750845190199;
        Wed, 25 Jun 2025 02:53:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845190; cv=none;
        d=google.com; s=arc-20240605;
        b=IG5+aFDnolhKSAgtnrTnINSScqabvYi1jzikBh64hJwJf68B0TOizjoc74pZAelOc6
         TExRUQ5dJHI1egkoPjsEAU71z5Zx2QQJYgIp1ED0g3W76h8r50lrC/tueAZG9TEYpzjf
         vy5ijnQGP4frc0DeCGxYnt04HBHkx++ZOM+t3WBsoA4MTWTCt+GrNNkF644cRTdDp8in
         8Vi7BTAVvs83UseMhPMDq4wJ5Y7Uy1vsy/nngHxY6jzbBtoa96sO5jgm1wAe7dM/6J4Y
         X2Eocl306EIXrZgfg7d1HOxBALJshUrqIvXj3baml/zwffM2/Lquyx6Q9i9Xp31WIVOy
         kPYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GQiI3pji6r3skZCyeT+2q6FDZmdcyPERVGy1ENHzh48=;
        fh=1mNT18I0DjaObveDWTkP1uGFd6Lwt61wXwdrp8Lp5Ns=;
        b=awaR5C7XGIXowNhWhvLy75FREig0y4SgGxBDb29QeK5XPJ4vggy1Jxa85d1+q/ft4R
         6ug0fpkjPuBre6orL5eEJeNvbp4+ed3vjh+1tCnzb8/lyu4EvYRcADIwSG4xGlXDONf/
         k+7Pd+bNOb7Vba0dcCOvbu1F9o9Fh104AGyGoVs3909fYJnGcJHiR+EqBtovAAIHR2IV
         Zh00hbEX8hh0+pczEq+3WzHa3hNU2lBqnJJBEtbwnPWOe3E3FeYDYuVvr6t4LcWQxc4M
         pVc4r1/C8uzUD3mtqdoudIuGsERufa1I80L3oL6A48oFQo+k6oy1Wk8PB4EZHb+7h/vc
         SiVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FgnNVOZ1;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e4153d94si224436e87.5.2025.06.25.02.53.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-32ac42bb4e4so55678811fa.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU36VxsQ17h2Qm5Whb5p/8XTHVXR/Vly8WmJxWHagcmyABwxpCkPsCEjjzNKlN5GBsak71bAzDojVE=@googlegroups.com
X-Gm-Gg: ASbGncvjYAV3MfWYoyTBWO5MEicxPfYK064bc5RYopmneMlOB2h1nBAnTxKlw2YHBhW
	W3tXf/A/zpJXVCIN6RJRkxcZB1wGLdbgKiIfY847WaGPR6dOndTNYrQTCIR0U/2TWyD1SLcfRcz
	KYHflTwuOytqT1uAjLhApjMfF64Xxi+wElURtrMAfm/Nm5bnEOUibiKpbrztEkm+YHiiglhS/7a
	wBs9SBa9ucXJJKUKvF/O3FJq1ut8H81nIHzbSCT5khzuZQifL6nKYHyLoQWnFV2KpnPns19I4qJ
	6l31t6bEE/Ym+z8Ig5GsfWz5DQsYbhOotZpvyi2hPCvxxq1Os75z6eEBQiIAKJhqkMFoKlMryFU
	B6ynBE6zYsKAPi6Si/8toRtnADIs8gYLp3R1x6z+e
X-Received: by 2002:a2e:a54d:0:b0:32a:7270:5c29 with SMTP id 38308e7fff4ca-32cc6421a2bmr9358961fa.2.1750845189565;
        Wed, 25 Jun 2025 02:53:09 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:09 -0700 (PDT)
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
Subject: [PATCH 4/9] kasan/xtensa: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:19 +0500
Message-Id: <20250625095224.118679-5-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FgnNVOZ1;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c
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

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/xtensa/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173..0524b9ed5e6 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -94,5 +94,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-5-snovitoll%40gmail.com.
