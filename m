Return-Path: <kasan-dev+bncBDE45GUIXYNRB7XO5TAAMGQEAKCZFEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 86D76AADC94
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 12:35:44 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e75b87a703esf2905332276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 03:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746614143; cv=pass;
        d=google.com; s=arc-20240605;
        b=jjunrYv36gBWRVD0O3ceHvvNnHhjPo2CFYjmAjzYfpfJ7kQ7RrntdHdgwJ7n3kR1ZN
         PbFGkuu1Iy8ey/a67Uk7BO+Y2IAj62g7ftxkTnJTHlEjNo9KoqJzUhjvHTDDExei8N2M
         v6hBzFbIZdtzE7dQ7YC6tYbkP2Jdpf7G3oNAUpF8HHEwzesg7biSpoBqOL31eL3xPnzt
         U8lY53ImMgjV7zjxy4Y/0HSKj2YCVbPpQxxyVRFQ0yAAFuI6+DY+mY+72JL0Whafw2Ef
         nEZsZClH7gcRQ3fwP9JZ9epcBhXUu7N3vLMR6LtD8t5+fI6X8Cpp5a7gdiMo2SqpKkWt
         RBaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=ICBAuaGU7jjNvAJ28O4e9kTnwR7fsJFDRo7O1JfLaGo=;
        fh=+lkRrLLPEKDH5AZx4750CbDown4rcduY2gsJV5lvIv4=;
        b=HCWI4awwCco2cuQ97dnGWZRuOVWOtT22kKbibukbKU081p0366QidZ9rYYSaHpOzx0
         EhnrXVP+ZBLxpNDt8oiQjYj4cB8QaGt96Jw/WJ9aGdxPhWN9AZ5gynOQOcOwiVXPrG57
         YA8jJIaoWJT5VnLUC8jqe5EfvJKHhWXNMthRHe+DlAx9Zu8nnhuiThD6k6KAUrQiMKa7
         oHv4OjqrJm5vJQ3ER9n7yah+fnWIpuO4kXOHWsuhBrPNmDw/bFoJbNSJOAcymIWz09HJ
         Eiyww9iFv5MjeMJTeLEzntpp3bT0Kw+5JeypG1RwtOaJwzVC0pKsF1CNwFtQdRHYHg4h
         SiLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="K/dPc3wQ";
       spf=pass (google.com: domain of maz@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746614143; x=1747218943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=ICBAuaGU7jjNvAJ28O4e9kTnwR7fsJFDRo7O1JfLaGo=;
        b=cG3e7BxdupBAvZknuIkDn0KhFJH7vAxIl5FikZwJr34IMgM6X7BH7F36LI0PwFbmLV
         M5iZZ2jzAN2xLn3DlFkNeBOhPj41h7tKoup2kLQ33OH+l2NKQaqeaFS2+67uBFgRltAi
         65tLPv3AsVZSdiAWje2JASMnkFB6mqAp68p3w9u+H2e0otql+d+NQn9l1h561DOTxXjo
         KxZPqhNgOpPo1dn+ON0nfLa+Hh2UBDqo/n9XcYzEQ2zNO0BgKmmSxlH1CTvAHmzjdo5R
         2ZgE1+Kpj9fgYJl//OmY6oR9ZYH0PmF6vNKTLg+XiZp6iW/QFy1kpQ+xNPrZ/sAN9+vV
         NeVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746614143; x=1747218943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ICBAuaGU7jjNvAJ28O4e9kTnwR7fsJFDRo7O1JfLaGo=;
        b=rOLPZAjwMgynNBTKlairFGhFHEflEbf9UHLBVDXvwIFLruQO1wPzGVRzYGkfMIQkA5
         5fmrxa2ZzmCM2Ww6uXjKIxY4oqVl28lbmFRACz+3MdwPxnBt58Immx7WKgcvJ3u1I9Z8
         09Cc00jwktQ56/YQwCsplvLE9Xai/rmJMGFl0UhZbo0ZO+dNpI7u1HbNwxbFtHg6qAI7
         xqsVn8QZTcfPP7ruvoWPgXP5YUSn1v7rfURI1KQZLCkQk4JqwcEBAT8kspnIqAT1QX+v
         QDNAVNkkTvou5kxUehYAWlCTWmiXDaWoZEiVs4f0bnGxRnxOyPHLtjAbWIbNRAqMWmyv
         xMXg==
X-Forwarded-Encrypted: i=2; AJvYcCWsJ19jEnsCzzGrq5pHunKhFJITcFpM33bW7S6agdwXBo4iNuZPxv6rqRa7OvhgDC+z5Nb3jw==@lfdr.de
X-Gm-Message-State: AOJu0YxpYtnWAwG5ReqwZRwDTccGQe1UIGI5imm2HBDwR0L+61lYveOY
	CvYkE7960t4fd37gZbdyQLHHKdcoISHvmjKoXK6Pe5crzFYrXHRB
X-Google-Smtp-Source: AGHT+IEFRTSX4ixnrlYdTFKr193dX7eqHHyf1YS4fnAlPriMYPgvCis/GuyyVjPYqnHr1iL8rVZp+Q==
X-Received: by 2002:a05:6902:1009:b0:e72:efce:b24c with SMTP id 3f1490d57ef6-e788141a645mr3606710276.33.1746614143019;
        Wed, 07 May 2025 03:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG1MI2LlGaWr66s3wB1m3cCBtAbQLz0QjIFJMVq6I5A3A==
Received: by 2002:a25:e087:0:b0:e74:7ce7:2dd8 with SMTP id 3f1490d57ef6-e754b311c0els1625319276.2.-pod-prod-05-us;
 Wed, 07 May 2025 03:35:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhdDHal1XX8IgGuqy7+ZSp37GRf/DM5moAuxE6RB73e3rLvDriKyvgNCtgLPz0rmC4CVVgdB3nlpM=@googlegroups.com
X-Received: by 2002:a05:6902:1890:b0:e6d:f0a6:4cd7 with SMTP id 3f1490d57ef6-e787db4b3eamr3192863276.0.1746614142084;
        Wed, 07 May 2025 03:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746614142; cv=none;
        d=google.com; s=arc-20240605;
        b=TyVewoWTRFjg/ZLp3q1Hy98n3s8xxjOcFqU0BVW2LS54I/UGxqifugTIuny8pjtAK3
         s2urEbKtY4zVh1fr9PFpsBTzqFhXca7VxySdrPjpO3/5yGZRZInVc5kt3MJz4UhYBkib
         pxF068sI3awo+H7Uzp2Ng9CPSeii/Ol/Zz0uFyUor06CZcGpPhgAIBHC45bEyvivcovv
         VAQcjhl5UuRoHM5DachSXa8d9IlCv7dW14+K7m5/Vpd3wlokGUYtycqZDuxSBJiWZBLV
         bvmIJ0QfS0j4sXseV3/6qG49rYn9b9vVGSep7KnAfPcw1bLhWo7Hn9cSn5v3QCt8Vhhj
         LCWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=0HP0vUR2bTzalaFuDgbBFLEPxeQSCl21cv9JOxMPXIc=;
        fh=o22x+YlJB85YMf66D8nPiPVLGivwEc6c/9SdpebdfC0=;
        b=gMlaYSLotnjFGmMOhqyp4FK/vSaVWhs5sAUUpHXw07YhJZsgesvDga/yw2NOndV5F3
         qOtA1IZqY/ZiFk3a7OW2cg8jqBS7kO8LfUIfHENWsErLRGX865lD+/1815oOD3N5EJEz
         +y37CMoyENo11i9zK1UEAiuGO0PFF87XU9SKhXkRDSmjIEnGv9EH4vVANCAO9Jbc+HzW
         5XhvzQ4zGCKlwEcSM+ctrrARI9RZkbRRIjL2btyb3J1ZARBzyW4Fj6mDsC7te/70IIj1
         ll7UL11i7IqW2kcuIzEEonqvCy4bSeGiZWyiBtVGWv8+sEnk98Ltz6SmMIuK/+I3r5xU
         qbiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="K/dPc3wQ";
       spf=pass (google.com: domain of maz@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e75fa106fdfsi129727276.0.2025.05.07.03.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 03:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4B0895C5D32;
	Wed,  7 May 2025 10:33:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29164C4CEE7;
	Wed,  7 May 2025 10:35:41 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.95)
	(envelope-from <maz@kernel.org>)
	id 1uCc7n-00CZos-0Z;
	Wed, 07 May 2025 11:35:39 +0100
Date: Wed, 07 May 2025 11:35:38 +0100
Message-ID: <868qn8hfnp.wl-maz@kernel.org>
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Mostafa Saleh <smostafa@google.com>,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	will@kernel.org,
	oliver.upton@linux.dev,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	hpa@zytor.com,
	elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	yuzenghui@huawei.com,
	suzuki.poulose@arm.com,
	joey.gouly@arm.com,
	masahiroy@kernel.org,
	nathan@kernel.org,
	nicolas.schier@linux.dev
Subject: Re: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
In-Reply-To: <202504301131.3C1CBCA8@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
	<202504301131.3C1CBCA8@keescook>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) SEMI-EPG/1.14.7 (Harue)
 FLIM-LB/1.14.9 (=?UTF-8?B?R29qxY0=?=) APEL-LB/10.8 EasyPG/1.0.0 Emacs/30.1
 (aarch64-unknown-linux-gnu) MULE/6.0 (HANACHIRUSATO)
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: kees@kernel.org, smostafa@google.com, kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, will@kernel.org, oliver.upton@linux.dev, broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, nathan@kernel.org, nicolas.schier@linux.dev
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="K/dPc3wQ";       spf=pass
 (google.com: domain of maz@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

On Wed, 30 Apr 2025 19:32:23 +0100,
Kees Cook <kees@kernel.org> wrote:
> 
> On Wed, Apr 30, 2025 at 04:27:07PM +0000, Mostafa Saleh wrote:
> > Many of the sanitizers the kernel supports are disabled when running
> > in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> > (and makes more sense) to integrate than others.
> > Last year, kCFI support was added in [1]
> > 
> > This patchset adds support for UBSAN in EL2.
> 
> This touches both UBSAN and arm64 -- I'm happy to land this via the
> hardening tree, but I expect the arm64 folks would rather take it via
> their tree. What would people like to have happen?

FWIW, I have now taken this in kvmarm/next. A stable branch is
available at [1] for anyone to pull and resolve potential conflicts.

Thanks,

	M.

[1] https://git.kernel.org/pub/scm/linux/kernel/git/maz/arm-platforms.git/log/?h=kvm-arm64/ubsan-el2

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/868qn8hfnp.wl-maz%40kernel.org.
