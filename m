Return-Path: <kasan-dev+bncBAABBHFY6CVQMGQEOK4OQPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C95814468
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Dec 2023 10:27:57 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40c33d8dfcesf4188545e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Dec 2023 01:27:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702632477; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8M7ZsBbqI9aaCPsdYRmhHTR7iZ8h2NuWXltqEKgKRFosVcVBJu7dvfaZcBx0y+z+m
         X2VBI1IXTR4vslnRgx2tHdXDVs6SyaFu07djluf7Bu/JIWxam0wdctE292HhgRdr7h6G
         jLEoElE/XrQwFCFayJzBobYaZ5lWZei5ENKx4MiD5+xV5qfv2O9d30IM/3iNl+kIv8Kx
         tEQDhOt5Ca4JvE9URTgQrmMec+hGK/gp+GrQPBlQG5pKSJwoWktTBFpvWFS86jZA4lQY
         zh/+fPIOgaKdnw3KbnFgKWV7ymu+SkpNaMgx9wM/nL68xL77foByokOPzG5Ai3QpqJmL
         TPIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=pMb6prTt5CsSh2uxYS5m8Y178qMkCug1ubkIyMByoQk=;
        fh=S6fFz52YCbsdznBjLtCSQN33hfexsgsFtw/Q3a/cb80=;
        b=D0RcmmLhl1uDWf2/hHuoj914tq00WWWff4rb763Qwj67/mhlOKoCpvWUVfMlZzU8xb
         IUBoEaceyFNRnMZs0x3KXjycwMIz7INUWyTbmO/BgKjp9sdNg8fW0YUi3jGGjW1qO0ay
         mN35wW4fK6teBmaTpUUzC/Xne6bifv+5a/KscUmecZxRmOX3T3xK3h6PxRER3GJcHaBq
         j+M5lpoZLWpGXdX84EdgAsylIYXJHRH1eMNKJkJzO66rQzkwYYGUIXKab2V3ybb6A9fg
         4QhmmQjSLNj0NXsdPEudwg53MsRBycqD9NUVZX72OYOL9esIn3jtQxERK87/DNgZs24+
         3/BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ar+MEkcH;
       spf=pass (google.com: domain of aneesh.kumar@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702632477; x=1703237277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pMb6prTt5CsSh2uxYS5m8Y178qMkCug1ubkIyMByoQk=;
        b=rhsoI7tgG6xcuuWv2KaTK0i5LQETwd59lnxw0Pmkz2AQSiKNc2+IFXVU+ObijDIl+m
         PqzqBVWYiZaY5PzzL8ignzPFVD1Uaw6RZgCg2/TyQYxBIOuW+do0Xt12qWRJgA/n6RqO
         imAM+brW0HF5jxIf0YRy7rYZExjCsOBxcWfSFh6slRmU1kQAhzCPCDfWynVF/gUEIoNa
         4F6rm0yETvKbbowQgAjjQ6k2RIKqL2AAZ7NZYMiIIvegPzOi3M6WU25Q7wWatnw2B1H6
         DyIREMS8RaIb6rKlL5sNnKdDtL4w9rAT/L7gYl18/MTFBzNk1Q3Qo1UfsqW8H5OtjfOf
         3J0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702632477; x=1703237277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pMb6prTt5CsSh2uxYS5m8Y178qMkCug1ubkIyMByoQk=;
        b=pPuH/poCgA5S+l5yG5J2eMV1cOUfPVkioGGZh9QQmZMeHC9euC1+yWYxFOfJ87xtFX
         J7yM0eAfXhsNv2SYOzO41wphV9zCBrCFEawTdyqzrCsrlpf514MI89S108qNwcmQjtAh
         V9VJAvF6wIpTgPA9Ixe9eDjZg9O4Q6AVvUchS0Vqih0er5/C9IQ7fl6kV01m0M7VURM9
         qHi8sY2uhSo4sXAz9K/3li5c2TfDLcMKS27qs64FgpxnxeR/emjvHu9hjRJuenUS2lif
         ExdL0wXnfXkTxL5JGb058uEcl+HxCaphUmH4tgUO7szYWGX/Lnjw8Hm60gjk3shu8D9D
         0TYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwXrxS5jbwLffdeIotGYEZdXBAXEB7JHl1XdOvqDkQkMvOPhICc
	AD3hI05Yykn+xrcuSfi0y08=
X-Google-Smtp-Source: AGHT+IEB8XLhQMCHzAH3Ylsi7EDX2WtiLB422B+YoW8iQnlOCjFrOhzLhxqXWKsg/klEiLt+LYr/Zg==
X-Received: by 2002:a05:600c:46c6:b0:40c:2ba6:809 with SMTP id q6-20020a05600c46c600b0040c2ba60809mr5851279wmo.157.1702632476252;
        Fri, 15 Dec 2023 01:27:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9a:b0:40b:3977:87e3 with SMTP id
 bg26-20020a05600c3c9a00b0040b397787e3ls354603wmb.0.-pod-prod-05-eu; Fri, 15
 Dec 2023 01:27:54 -0800 (PST)
X-Received: by 2002:a05:600c:4301:b0:40c:27a2:ea90 with SMTP id p1-20020a05600c430100b0040c27a2ea90mr6358469wme.136.1702632474563;
        Fri, 15 Dec 2023 01:27:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702632474; cv=none;
        d=google.com; s=arc-20160816;
        b=rbPiBLGBU9UJMuPQoOZOaFpPcbj9X2+lkkT7w3ufCb4aRp5u50hVNsTYj3BKplxnmr
         Ky2P6BDUOHMHuilUVEvFPQ+ZUYqDGeZ37OCdKrGVEbJuxEgRvqLNF2sPBvGsQKCH8DYB
         rre1MRhJmRTNsl6LKqLS7GEW/WbmhlH2HTd4WAO86mPAougXPfkivE1pWaoseirQUOOk
         +7fz0h+f2lIaK+oHqjAM7Euvi2ifsLTVKmTkJM1gCcSQ+3dzmYQden0tduiLaa5CoV3s
         34HiEBDx5unXBAhLiz89x6lfu7PvmLhx0wsFKcDwEPUxNTuEkXkN7WMKHiIIqIoWyu6b
         norQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=hYPAQIWLk8khuqHUwuIA1MRsSUVYCv86odQdWoEDCdQ=;
        fh=S6fFz52YCbsdznBjLtCSQN33hfexsgsFtw/Q3a/cb80=;
        b=T9CSLvtTZvUSOSaQuFM/xiNSYrxDfqAvoSvhZRZtHi2AciYjjrXZR1vBo+Puoo+N/i
         UJ/JrRgW2LNvsvSdbbF5FK7w/jUej7AxGuGh+zDRzlJbMwNJcw+Q5QPYhL1mYNs+ASh7
         7/HGoIYdGHRSVs/ojUoofPjjIkH4s2ffqRGbYrhfmY6Za/PVstoqWcvxAM0BpJaVwOEW
         cwGBvvSKTXmBzIG9f5JvjmXkfBJSAGTt4eqkHCuTJa/J1mrG1hfUvWFl2U3Hpykp4tca
         xE56zVyGHTIkRgZ3JIF8Yb5UN7jOrJpKG3y4I/o4SXvn8Yeik6wNXib4j/lo7W6L6+PF
         KVng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ar+MEkcH;
       spf=pass (google.com: domain of aneesh.kumar@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id k20-20020a05600c479400b0040a25ec1cfesi41108wmo.0.2023.12.15.01.27.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Dec 2023 01:27:54 -0800 (PST)
Received-SPF: pass (google.com: domain of aneesh.kumar@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EB562CE25C0;
	Fri, 15 Dec 2023 09:27:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CDAC5C433C8;
	Fri, 15 Dec 2023 09:27:45 +0000 (UTC)
X-Mailer: emacs 29.1 (via feedmail 11-beta-1 I)
From: Aneesh Kumar K.V <aneesh.kumar@kernel.org>
To: Nicholas Miehlbradt <nicholas@linux.ibm.com>, glider@google.com,
	elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: Re: [PATCH 10/13] powerpc: Define KMSAN metadata address ranges for
 vmalloc and ioremap
In-Reply-To: <20231214055539.9420-11-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-11-nicholas@linux.ibm.com>
Date: Fri, 15 Dec 2023 14:57:42 +0530
Message-ID: <87ttoju86p.fsf@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aneesh.kumar@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ar+MEkcH;       spf=pass
 (google.com: domain of aneesh.kumar@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Nicholas Miehlbradt <nicholas@linux.ibm.com> writes:

> Splits the vmalloc region into four. The first quarter is the new
> vmalloc region, the second is used to store shadow metadata and the
> third is used to store origin metadata. The fourth quarter is unused.
>

Do we support KMSAN for both hash and radix? If hash is not supported
can we then using radix.h for these changes?

> Do the same for the ioremap region.
>
> Module data is stored in the vmalloc region so alias the modules
> metadata addresses to the respective vmalloc metadata addresses. Define
> MODULES_VADDR and MODULES_END to the start and end of the vmalloc
> region.
>
> Since MODULES_VADDR was previously only defined on ppc32 targets checks
> for if this macro is defined need to be updated to include
> defined(CONFIG_PPC32).

-aneesh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ttoju86p.fsf%40kernel.org.
