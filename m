Return-Path: <kasan-dev+bncBD3JNNMDTMEBBS74S3FAMGQEJFQP4XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 68180CD1EB0
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:06:21 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-4511a6fde00sf5213683b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:06:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766178380; cv=pass;
        d=google.com; s=arc-20240605;
        b=SJ7R9ZdRIprA8QXHesQZquh9uwrnXfadtyFbwyj6y8gwn7EIQ/1HJQu5+ZDXBCXUvT
         SAUDBjnp4zANTg9LaZc4zXgpxLp3XYoWf6HbH3sjYkC2/Wsuu9Cz/LWn56yffk++QEqA
         /nw6zSLMW4ftqa3wwrQ2Z8LykiHVSHABNBHciZfaLNa0VgGL4aAD+vWZy//uN0Fe+niX
         x4/2DYRJXhlcmBKEos/gGJBoD+AosZXkhtIv195MdCKSwT6XnH22VmZ3T5mpKn5sc1kF
         PJPcaLfGacUO7u70wB7uzyHjoD1M0PL+GeNXoqdp1xTd11/ZD2Bmi0PCWui2INFF5MvN
         0ljw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Usbof+DkCDjSuPv/F+sLurIlfYuHOqNtPy9h/vNnIjY=;
        fh=DpW0FXdEtFObGUiV9xEJQYSmo5y+9+6U/FBbK9MQ7ig=;
        b=Ro5K/IAIAqRPbYuW6ia9Bt5QHvvT25Klj8DV5IpvYltKM20tobxWyAcDFnxwEdYOpl
         DIHybIey+AvZzFqXeiiZrvTo1WpeLTAy0GANvabBBskrywBaiCXtOvHrNiT5Vk51W/C+
         uQsmccSqGtS3IwzPHVxIMZjGViW5jeAipNSyBcpd5uBxGxSQdomgMLUh0Mcm+6GQuZOt
         omxhOuSa6/ZadVpRKe8bgBhdTsYsLgP0gBlcMWbRA7sdUr/iyAPeR6kbEo+HJG+0Pdvi
         +kOl+g+cgVnKksJyjk6/ruWqs1mEH1253a0hSEMhgdjjV5vouMsgYF0u5QcHTHkjwxeR
         Jriw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=biL2fFLA;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766178380; x=1766783180; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Usbof+DkCDjSuPv/F+sLurIlfYuHOqNtPy9h/vNnIjY=;
        b=b9kDIhcTUJxja90VWlk7Dp2P5QJhwV4pI0cStbPcU+NVei3NS5QXpFHb8qRfP1xoZH
         crJ7O3P3DdAtce935xsthBfFCH7nmMEKJnZhAkOXbotO5/s66FZvVOA8CjzNHeicVaus
         ZC9vAwenKGNwm5lHk8ifILZ809AE0YIy7huudg5HdobcDnsmFzTQpuG3iXswaspZg3M+
         NM22lycA4G0BVtk5LesCOsraZjyRFqAnm7ihpx7NUB1Dgce33QodSE6526YZEKfuvmOS
         j8Z3LIqc9u6QtpT5Dax8dg5U0tfH+mgqPULJ83OA/vXdW38zKERnlMQkmd6rB1kPFy63
         0C4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766178380; x=1766783180;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Usbof+DkCDjSuPv/F+sLurIlfYuHOqNtPy9h/vNnIjY=;
        b=gC8VW8PTmY41YdBK/yDz5t3PKNSqRte6Iw9+IhA5YMOR8JyId+7FKQZYDI56Xn5eyn
         71NVbhWNuEz+XHEf8qI8nKv/zQnbevhDh2FKez8L2gflTc869ejLGK5/aDM6QSu/Ss7z
         Eh5XkMbv8/jPo5e8+7j9EjMonzdOe8Y0XAq87wGOIR985sYriLvuNrf/+XITY96FQ22X
         MWjZii/zvwMuxvAO4GSL+xEaIEyLbQxV7J85EOyt8IDrhk4cB/rLG2fCezM/8MbrTAJ5
         N8yK1cXkSXvvRf+cn233r4tZIInCjdCvZQjyRXyV1/xwpg0wiK4ObRb+oEXOHK84eZtH
         ORAQ==
X-Forwarded-Encrypted: i=2; AJvYcCXsbK6aeJB4f9gLwVjWWhEtyEo5776MecuVE322e+p2WsW3GyTrCURft8Qiq1igPe0jN1vIpw==@lfdr.de
X-Gm-Message-State: AOJu0Yyfsc6KD9VmmcEnuUcsuepd43gX+jekr0yzPZP1hur7VQbXAz6s
	Oehi/94qbxylYjOWzwTtdQhqAfz/18oZbIr6zszwIrelreBu6SmTWMW0
X-Google-Smtp-Source: AGHT+IH8LfVSZkDnYkW2QM2oxyhRcsRRgeaITrigGCJeaSnW3TcxeXL5cNtXcOAtcSxv4F/SDr786g==
X-Received: by 2002:a05:6820:5054:b0:659:9a49:8ed3 with SMTP id 006d021491bc7-65d0e1c0deemr1766622eaf.7.1766178380086;
        Fri, 19 Dec 2025 13:06:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa0iQIchpf60BOjx/voP7b4LmMJnad0JiXl1nqU7HqMVA=="
Received: by 2002:a05:6820:259:b0:65c:fdad:9421 with SMTP id
 006d021491bc7-65cfdada23als637568eaf.1.-pod-prod-00-us-canary; Fri, 19 Dec
 2025 13:06:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlYNmDQ8Wlfht2bYHXwBXcYZUpRJKIH+4WI1H/uDCxit36FERhlM+6xf5tVixUoCxvTVJHyhXHt9s=@googlegroups.com
X-Received: by 2002:a05:6830:2a8b:b0:7c7:60d8:9d7c with SMTP id 46e09a7af769-7cc65e8f3d3mr2702377a34.16.1766178378611;
        Fri, 19 Dec 2025 13:06:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766178378; cv=none;
        d=google.com; s=arc-20240605;
        b=Lb/b03dBN9+CZwQMlqGdJ+HLCUtp2NAfkaZppHS0o9KnnI/SghXOPdcLCI+9vDnIRA
         xrkhmtyrgODvqUWgdAvQRLDzHov3uIqj9Xkgus5nzHiEcC7uXccqZKAnZ6gHlcVQRIZ0
         tqSA17oW3UH2xoZanb5Whhx1PvDf/ZlTVmQiIgvlhzF9Eeo/xYHAnR6fCp5oqGVpUPm7
         RC+XIDMq2ODKB2e6wsAxaNnvtvBxq5h0We0O+auCKb+4fpw8NO2iWUCZX4RaSDSmpOej
         ZUlXFLXb/JP+PApemY4XHgUMStYT5bHD4sahFpTzJ7s/5Xf+f0GJqriAP7gDPu+lWFG9
         sHYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=smhZ+HMOPx/2qzqSsA1Ia7Ur+56UUYwNTrJDmSp3Lho=;
        fh=O3lw6u07x8QfhLXTqEFRs4Ygl3k/Osi5MnSbKb807eg=;
        b=f1it/uPDx9fqTFtsy0PBNaP39fH+0ubyyqsZCcm4gg75Ya3jn4ySL7BmujZhz2hzPJ
         oufW9ie0n5dwcJmRKP4JEt6JiWxFRpk7raNuKU2XFdvJTF8KP9scskSRwcz13W34dbIl
         vNZ5muG4ewFmN3QanAbLk3PCFdwrxaXCCkqCs7hZQzzluunX4D6S5cwEo++rJjUK53of
         WQDH9O18BtSqwjnhOO0qWMjYS8JEhhiIIcvmu6U7kTkXYLTyfqqynHFu+Mjz82SEKYdz
         yIWe3zFHR+uEva790rb9BsFkf1nyxIXLJCnskAAQkUJYvRvrj1OaiBn8gRMkUcziQNDR
         l5rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=biL2fFLA;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667c988esi344340a34.5.2025.12.19.13.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 13:06:18 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY0Sp0FgnzlwqPk;
	Fri, 19 Dec 2025 21:06:18 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id EEu5ZjhUq7eo; Fri, 19 Dec 2025 21:06:10 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY0SP39w9zllB6t;
	Fri, 19 Dec 2025 21:05:57 +0000 (UTC)
Message-ID: <8086c568-9386-4231-b928-3e887c8679b4@acm.org>
Date: Fri, 19 Dec 2025 13:05:56 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 22/36] um: Fix incorrect __acquires/__releases
 annotations
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org,
 kernel test robot <lkp@intel.com>, Johannes Berg
 <johannes@sipsolutions.net>, Tiwei Bie <tiwei.btw@antgroup.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-23-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-23-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=biL2fFLA;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 12/19/25 7:40 AM, Marco Elver wrote:
> -void enter_turnstile(struct mm_id *mm_id) __acquires(turnstile)
> +struct mutex *__get_turnstile(struct mm_id *mm_id)
>   {
>   	struct mm_context *ctx = container_of(mm_id, struct mm_context, id);
>   
> -	mutex_lock(&ctx->turnstile);
> +	return &ctx->turnstile;
>   }

Many "container_of()" wrappers have "to" in their name. Please follow
that convention and rename this function into e.g. mm_id_to_turnstile().

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8086c568-9386-4231-b928-3e887c8679b4%40acm.org.
