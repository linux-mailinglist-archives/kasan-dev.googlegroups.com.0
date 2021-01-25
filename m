Return-Path: <kasan-dev+bncBDDL3KWR4EBRBA5EXSAAMGQEASG3AYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F559302A9C
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 19:46:28 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id i124sf6774362pgd.4
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 10:46:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611600387; cv=pass;
        d=google.com; s=arc-20160816;
        b=FzgqFM9A/8LJfzAewiSWx3eBiJIRdheIKeRVovvbe4eV3mcdQr2Sz6pvi5bx4fPv2U
         vnyK9Cc10xS7DFpXBnZ4mHxkYujroTzMKcyKwxs+VE/kuxAQ68y+IbgUd+OS3+Qhnmx6
         FQQyehm7jcedey1D30s0wH3SdyJZynXCF46M8jpd3Ynd+BDCmHJufmEOAw4lde29LzkM
         GiI74W1QqOZoduicTYWLZP0zDeISd+wID3mrrYXp7IS1isxj8iTPgcW7fM8krOmOk5e6
         yhVmBeBrzghRal0bDhZEM8cksfNLni12YQVhDQuKIZjvQ3x40J3O0zsMBr+pYYTt/J1S
         ZARg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=0qUnnozd3L5VDv0Ri3y9UjC+q7tQZnj+jFFTzJbqujw=;
        b=GdiRT2L42R3hHETUuTwkIEtJza6LU1lNaUTC3/GxqCriY0hjr7CDO95DDn3ize0Ht7
         KPLk9sRN9aFQs5SSAT9G70swDIsA0Vqajp8Zzr/CzxmRfcexhUUi8pswHvc6A20+SAh9
         KKsjTw360CmpqTgNqQ/Z6vQbK5Ca+ax4g8G15Fk3eVf3jdHkhw6wWR98Tw/vWeABCGuT
         K/QUBCpEOr8HZGmduWaZ/X3DkZLoOCjm7AciVQPK9dzbuBNHvTGcygzTgDdRuNypplyc
         yOw4a1zP97yODNbfQGOMZ48SZ6Kad1vOlW4EyNSXyq6hbLyj0yzq3TKdAWVl78kn0GU0
         jChA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0qUnnozd3L5VDv0Ri3y9UjC+q7tQZnj+jFFTzJbqujw=;
        b=ITfLzMspain1kC6HqcdVJ8ifSe5A2H7/kS4J1fXrZipoE9ytoXn/YpG6e4aYhWABix
         DhpqkdPKnbCH6RfnU1cX8KzQd7bsFueQiUe2YQYJqKU2yF45zQXEePBbCuZgUYezlm72
         Hf6zXSDpS8WEf7ZV7+KN/dLPnHQmB4qQI2u8IS7N6Nmh6EIVTNpPpO7jH5THGTTdtqsr
         TGT98hVg58GNLcf4ARTEMJyfl1jq1GSuX3heK5hhQUSp6r4OumZQ9p7VgbEYVEnsCuIY
         QnAQ/Y113CN1ewhDqlcWeMQ9aDX4EKO9gHiSVNCACx+RKa4S620m9R4r4dNIJoo6Wwv+
         SESA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0qUnnozd3L5VDv0Ri3y9UjC+q7tQZnj+jFFTzJbqujw=;
        b=dVIyIXl0EkxDXQpa/ls2SOVGZgvHaemUmTnNuhAn6cEA9T0BWBo64PZZ2z5lSc36MF
         H/7jvPol4ngmYSdzE9e1z0JgX8zY7kIx3fgMa7EC07QQ1RUmXSNLI1Jgug9WaNK0xXxW
         iVXTLbNTBrSIpCtfNi1QwJxvwRozKqI47t4u+XygOY5ToZYcQHUAdAOYSr1YvGRfTEkf
         Wg5kWqU9HT7gRgS5K5JqILLERDnbnAd3JjB8XLg7gsppTRb8mlLe9+q9octkCY6bGLd/
         VYeTlhmYIpXLClFcSOC5IUUvoWE3BhkIsKVAef6oAv+YzlibWZAXlD+gGoBXuf/azIcV
         rnSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328WonKyVxsTOGIhxbWpQPYZ87t264yKCukqCaH2uYZPG4PWVCc
	LopRVAqTySesnp3/5r/L04Y=
X-Google-Smtp-Source: ABdhPJzx8vtbNgqeI5SUVdJKhtWFZbPWrl4AF0+YyTFXI/7dr4Pwez8wVvT0IhC3bma78iS4W4Dbow==
X-Received: by 2002:a17:90a:bf06:: with SMTP id c6mr1580853pjs.220.1611600387224;
        Mon, 25 Jan 2021 10:46:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5312:: with SMTP id h18ls5107077pgb.9.gmail; Mon, 25 Jan
 2021 10:46:26 -0800 (PST)
X-Received: by 2002:a62:5b85:0:b029:19e:432a:2717 with SMTP id p127-20020a625b850000b029019e432a2717mr1710527pfb.73.1611600386649;
        Mon, 25 Jan 2021 10:46:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611600386; cv=none;
        d=google.com; s=arc-20160816;
        b=pdvBpu/JVrGKXdpDhMqwZmGQAimodimttB5wBVg0yxdKrW2A4bVLOJ6sUIUp0ZYmm+
         5/gTSrAwkgulmbwjqweFej4+E2LFKjSvexPoFsTyEQVlWVLJeqc8vpt7yyRqRMooVym0
         /5SElFPjLFTlhDSMkx+Xe45KfrddyNvYkXy3eCmLtrPU8pLAyFeewytOc69dqIhP5xQZ
         hmzCeHTqH/ftPf8gtp5H0MFMf1mKAFCKhviN0AFPxs4WD9fGl9w7a8cNSaui/l55K6Fq
         wXnUMrLkycKDJhg4DgLdeyUtV9p6lLXssmDGbWVSVWiaj9yKTU+KJWdL8xxHKZ3v9Vnr
         E3CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=kmfXk5wvWFwkxSsLQZnCMH5EPoJMYEckn3sXqlp32ok=;
        b=OtVT/Gx0NBsuvedckdYpS0RfkfCdVvZ+Z1vNAEywfXrq7siuhsNeT903ivSHJgwaTO
         pvSfUQHKfV5n7z5vKn0cDe+vKnVDdyrQHzpTi7xUPxk2U7ej+dqRmo3RdRgHlON7CF8P
         MeCRsnkJGRFKMmf2xL9m74reF4Q1ta5gAh2hxLvW+idZWUaZx9n9WGik0V/2PbYhkQJW
         YRWQ2aiGi7C0S1uHZLlC7yDREl3uQXSvZTTmIuZ6NtwFGR0Erkf+OTAPCXzyaPD6q0U8
         pOgq/qGRovAitD0ZwTj6gsVmMa7jEISj82kLCFYgohr4cCLQ3HPWVFO9qwfrdUN0w061
         r/rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 13si827041pgf.0.2021.01.25.10.46.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 10:46:26 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E213822B3F;
	Mon, 25 Jan 2021 18:46:23 +0000 (UTC)
Date: Mon, 25 Jan 2021 18:46:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Will Deacon <will@kernel.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Mike Rapoport <rppt@kernel.org>,
	David Hildenbrand <david@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] arm64: kfence: fix header inclusion
Message-ID: <20210125184621.GA32727@gaia>
References: <20210125125025.102381-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210125125025.102381-1-arnd@kernel.org>
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

On Mon, Jan 25, 2021 at 01:50:20PM +0100, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Randconfig builds started warning about a missing function declaration
> after set_memory_valid() is moved to a new file:
> 
> In file included from mm/kfence/core.c:26:
> arch/arm64/include/asm/kfence.h:17:2: error: implicit declaration of function 'set_memory_valid' [-Werror,-Wimplicit-function-declaration]
> 
> Include the correct header again.
> 
> Fixes: 9e18ec3cfabd ("set_memory: allow querying whether set_direct_map_*() is actually enabled")
> Fixes: 204555ff8bd6 ("arm64, kfence: enable KFENCE for ARM64")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

(it should go via the mm tree with the other kfence patches)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125184621.GA32727%40gaia.
