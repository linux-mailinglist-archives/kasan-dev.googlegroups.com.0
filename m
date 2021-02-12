Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSXTTKAQMGQEZNZJJ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE6031A381
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:24:27 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id z2sf79731pln.18
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:24:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150666; cv=pass;
        d=google.com; s=arc-20160816;
        b=FMId8wHxnDaasVFIWgRTV7mAJEPwyO06E8E/Au8gRbdjpUWWWw8vCzjwRtBFUvpoVY
         AinboogmcioAGz8EXf+8KD2wO1DYdtAhkLFWDLLg09R/X/8Dq2XRi6niu/MKgMYpMfRx
         xDyyet30wAO7A2ySgxKC5pWNa0GANLxA9/D+9E5puUgS6OZV57sQLQ7bRo3zQwSaB4U0
         kqHX3a+B99fgaq4wl5RZUr8Bv2ADKll2+OzUfZkvLHQsBz6kqzEUpbJFOxYYytk96ooU
         JANDU6b0OKQ/iYDz/9tOmInqA4nxT9/57rLQRD9bzdFsXn83MlNI1uqhnBO7ZHBzBtGk
         1WZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eCV1jS8z8dD9oEhmsV5H+xXQpAe3fh2WQjt/2RWOSuw=;
        b=ZNNZVpQvxYgr9hLbUskRm/AJQeKU2QjwBh+xE9nfbZyrynVnmUjULgIeGFyYfrZar4
         Hv9OjVKMjV8mFT1oHgqBlcu/xaSuA/1icWkNj6Zk4nprQRvLzyps240ReQYEZNrJynFK
         PEb+7esR0JUxQpNIQVuZGswith1hUsqPbaRoJNFzuHj9IEMkCxigNzzcznzxbxTGsri9
         LfoJ9HCeZRiY4ZJBYWsDXageLTKouuLV2VdLlTEc5dl9ibaejwYV9pbrOg35rFmESB0n
         FobmR4Q73c713vU3H7ookPn23yBuAN2MhF+dUwqG9Yz4Tc2x/+Co//pygUeqdJTEjLdF
         Hd5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eCV1jS8z8dD9oEhmsV5H+xXQpAe3fh2WQjt/2RWOSuw=;
        b=NRT+9dhjemv02yQCbDDoYRnZ7Ky/YOu18741IqXLDx7cvFqbFO4FgSv0JwLUbNb4OX
         ebEq3eTMiDhlQWnVKREzzkeVqPJqf7bW8ysvMobacIWFeL7Q4CM65y8l795oUhipO0vu
         om0Hl576tyTMt/MygXlfPayMRUevjTKIb1ZYvfEgVvNTP1ccyqwDw8sfHX4LYIQR32IC
         Zorid/6P/C85J1X7JTR/UgUoUmGG2a81z+fbX9mVNdftfKKqjEwqEM3y+8lAS/p3xwvn
         18/QNMgUdk7TenrVWop/mk8QNg4/9SqJEbkKuUQutrAQfGI9hGqWTQyYdKqbgUKUvCYr
         QdKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eCV1jS8z8dD9oEhmsV5H+xXQpAe3fh2WQjt/2RWOSuw=;
        b=BkkPKNtQ6xhEVL7SDhf8sRPsVpiIc9VEi1HdrBFfSnVyIS12GsmzhKUutYf5tKqoEw
         LdJ5gQP/vHas8Vc8wN5uUPjBqnkW5twJZFXQZ/m9XbVks4rcIstFxdWgCVZxFNJKRuoD
         MFjm5TOn98LBowBcJbqM7gD6+FMYbGpMJSysPDC0cy/zJEtHlKIq1scnx03wKRuPujpt
         NwNdMsn7ZYhOwrGsK5DrzjDH6Y8/7ilkQahcCiRAXUDU3cOz+J+z27d9+SKf3i+IVjcd
         TlFHkUssGRiEJ7xTrc2W4hRMiViZWUwzVQt8uagieb1z73oMopFxBZSqX0sJ+p7Orq9P
         XGiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331frV4eG+n+VInn6Ak0pN0caoRQTwAYHxcJpvGCUZ6Qok1V7ew
	FsltcqLZFcilOae4UFJk534=
X-Google-Smtp-Source: ABdhPJwXNXUcqkikOQcydx9go7RaCUKtWeLP9Xa+VbFCkJMZlw0LzxaLx8tNrOsHH+VUBdlgpnTWSQ==
X-Received: by 2002:a17:902:e9c4:b029:e1:805d:7965 with SMTP id 4-20020a170902e9c4b02900e1805d7965mr3539832plk.53.1613150666595;
        Fri, 12 Feb 2021 09:24:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:27c1:: with SMTP id n184ls3756147pgn.3.gmail; Fri, 12
 Feb 2021 09:24:26 -0800 (PST)
X-Received: by 2002:a62:ac1a:0:b029:1de:111c:c8a3 with SMTP id v26-20020a62ac1a0000b02901de111cc8a3mr4020152pfe.32.1613150665956;
        Fri, 12 Feb 2021 09:24:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150665; cv=none;
        d=google.com; s=arc-20160816;
        b=idANJJXBLdPxyemZPiDc8izu34UsoOdI1xK+gKTt3FPs7csJvgWeMzPNKb197k1wjF
         3M/MsfWscDPcO02I9NjDHh4zA7Nlm7810g8fBrzjSOGImvZmww6cs80lmhOFDfO7MuAP
         yB4hIW+hSmteoR48nOLJgXyidR8FkHo1m+tPPdI0dr/xfEHCHfB6C1KPr5PTzFO2kTCV
         iEuvb/3CnPeLh9f7jmOTYzQN2bjgFL+1fd7PRcsbylUD+0ppdDx1Jplsva0qmx4oQnyL
         cDItrGzqrEs3r+Ht5AT9JkUj/QGHiQqBAeJ1Q0nd0jNK9ZPMJ1oUuS6AB0Ux6gB81BiL
         yreA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=0pRIyDQF0o07RfZrHaLvNpZHERaXuCuhnpYraJMlS9o=;
        b=Oto3ZngHPAt2BLuTOW9ish9g7wirrdjlR1EVbNUnxdkE1Sqs4iaLWk9hmZbmiMn+X1
         SBH6ayDXHRKGzZU1RKQu237u50y183z/iqSvAfbbjgPsTXgpT6g3PuvxGfwUbpJgVfuy
         0MnHNXPwwXuaTLoEAyRXYpgff6NkSO32Eg1hSHPHfhIduEsMzNjYQv+H/Zwx/cgz+rsc
         Ke2Q5j8PFBhRg+3JeW1Rz4Tbfmoqi0PXrHvqipET4nlj80wYcjdsVjUsTg3Ad5qpndfJ
         NnN8ixRoIZfVg5MEXUx5wXpfXtekVIyIcK+wznR93iHObkYP9z872jTVlruxVMqV30V+
         r34Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w6si473783pgg.1.2021.02.12.09.24.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:24:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8136C64D79;
	Fri, 12 Feb 2021 17:24:23 +0000 (UTC)
Date: Fri, 12 Feb 2021 17:24:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v13 6/7] arm64: mte: Report async tag faults before
 suspend
Message-ID: <20210212172420.GG7718@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-7-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210211153353.29094-7-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Feb 11, 2021 at 03:33:52PM +0000, Vincenzo Frascino wrote:
>  void mte_suspend_exit(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
>  	update_gcr_el1_excl(gcr_kernel_excl);
> +
> +	/* Clear SYS_TFSR_EL1 after suspend exit */
> +	write_sysreg_s(0, SYS_TFSR_EL1);
> +
>  }

As per Lorenzo's comment, with this hunk removed:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212172420.GG7718%40arm.com.
