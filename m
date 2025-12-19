Return-Path: <kasan-dev+bncBDT4VB4UQYHBBAWDS7FAMGQE5HHZ2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43EE5CD230C
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 00:36:36 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-7c70546acd9sf3980057a34.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 15:36:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766187394; cv=pass;
        d=google.com; s=arc-20240605;
        b=V/NtCXajD+WTcMXY4EGQUlMmrCDwArvwN4ajJNOKf+j6yZt4zOGsqfB3jzoEiUOsHO
         u6AMxk+D/VgZce/b6jZQSPDeIsB8X6ReBLpdVyhgeCJJPhMVhVmSnUSbgKAeglE76BdV
         zOr59yQApEEHxaYH1zRd593KK3x99zL4abjIDHcbZhkckearyXg6HkxxiNCjc3rIa1A8
         7f7iqmN0DePUgiTYKrTA3c4AJD/FlwltN/72CRXb+qBzQoIo7qEliAw4JFYPkzXo1C41
         RqnOJcLxsUoqpwCnBwBoT3Y82qegMUyVSAQoPsAzvckR/TEtoBBYEeOHpKXDDpdQiFO7
         zlTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language
         :references:cc:to:subject:from:user-agent:mime-version:date
         :message-id:sender:dkim-signature:dkim-signature;
        bh=1pW7IuHuvUsuawX9rClILR+HqX2M0iyfDb8bUpx3N0s=;
        fh=Cq0n99M5TQMuBbwPVXQi3M2WDaOUbkiR2D90NPxNWVg=;
        b=fNM1VO39vZa6DIKgpdhrkYk1jqaqFSGXcVrKVJNgFFM3wOdKdo+ia14G4NckhN9OuE
         XQ4laKrDTlo3iM7ec7V5aZFyzFiqD4/xAtghD6KiQFUAkPNouw3zI5NpzlNpBdW9c8gP
         WXmHdCdYFps7xQ9M/fvxddZgL9T93/tr4DYftyC+X/6QjxbpBlhdIvzYzVH8K+f3bYm1
         52p0QB7LGx6sMOgSwSR7IxPCoU/mJVF9HZ46R7KZSErb7a1dyANxtHBuL36UJz9qVJAo
         nNCYWQ4kJ9bWgqoWPlzIf+Cjv5SaxwtNUQE/pqWG4Md4xEG83YDZl3UP58lnjGBm4J0Q
         ndHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JybvMGKe;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766187394; x=1766792194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :subject:from:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1pW7IuHuvUsuawX9rClILR+HqX2M0iyfDb8bUpx3N0s=;
        b=xDftQXS4eFu+evoEJwgEcNrdOaiaka0Qw/fSTme58re1iHc6EWFVW7xY7qMzVuzPVg
         uv0G9SkMVODoV+foJU3DeFE2qUBAA1eh5B0yuq+qZEeIIJuAIuvbTjHksWDyDHdeara+
         ophoxW1yfHHBdvAzhLcGUByL4+SirQpA7bhy2cegX0GzBSanTrc7MAZ/Zhg0kCf/ueH2
         SxSxxlgIWV62sOF87CbfGeIDXIscBeRv8+geNLSfiy1qYP/cEeNsr7BXvKK/IsMrxhgz
         68Vmq0f4Sg/texsksPlSVXTTKvN6I2qwtCtkBxzZN3Q6A0eSv+dGcb3CA9TFoWCUsDsq
         DPvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766187394; x=1766792194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :subject:from:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1pW7IuHuvUsuawX9rClILR+HqX2M0iyfDb8bUpx3N0s=;
        b=HZZpkRRvMi8yaetlmF21n+RzYTvXp+zYnzPrgbrAsOhOUn0YkjjY886SpclDbLeBxM
         xT1YB3LH7F3ZZnjNjWqIjAqiXmYJ+uHHzVF/cmwBkSlREmtbzV1EEGJLJcMnrzbSWtFb
         jbppNvQs8zIZ3Js+KY66zbCIRH5a++WPkTRZgm8mocTXcDB+im7Zz0VsjJ4vmW8pJ4s1
         a0t0Mby6xBklxF7az1/EbjNJq4xMs/V2iDwSgxGHc67hFzZvxRnZ4TBFBIyp2UYop7fJ
         K5Gtqi8b00YYM7ZEGktQl5TL5Byn7MHb45RFmni/MP8iBxY9ajHPt9saSyqUgJTWGbfu
         /9Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766187394; x=1766792194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:references:cc:to:subject:from:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1pW7IuHuvUsuawX9rClILR+HqX2M0iyfDb8bUpx3N0s=;
        b=PRTRkIBK6wPM5rSif76nZHAaH1FC3C0whFfZjLTQpXiWVymiGhWxm/7K9mYGjqoQVi
         v+BORNW9+71LBvzbB/mVCPGEJHmfDvZRrqFVF8uR4dKkC4Pr+qpzZObAw4XmGiZzL223
         cvmiMOS68pZunfqEYlnEWfW3pG53q/F/kSjtePz3ZOKQy29UpY1/WLnbvlA10V28wDuL
         X+DGkTZqoLI6IiO0lU02eNIrcTW/DvOF1uEQuGeojqpJIU2cLFDYf2zXRqNhtFJR8GW6
         Zmrtosbtugi2IggNHg7GfP2GhBBaAJMSEDCE4G+Iy4a/o0f78C/Q20aj7AdH7mwgI6xW
         gCng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBYem5oZyaqXmJ6xrKQXAOkUTEgRlCZdOw0Bzzbl2pUY6bxuMMVtNw0kPR42lNy14hTHq1wg==@lfdr.de
X-Gm-Message-State: AOJu0YxrkM8A0yEp/BEYm10wO0b3T3eLhrkPquhGLAPoXqW3qR0gMIA0
	revAEZRk1ptE8A+3f2SCB1nY+MyHUDLGiMqHMGhemZSBZAVzYzeFbr4h
X-Google-Smtp-Source: AGHT+IEayy6Ly9Ub/OUsyDKp7AbhQiJIqZRZU1RUhxGgQzjl8Hv/91pbN70KJA3zLeeG7kYFEu9H9w==
X-Received: by 2002:a05:6820:f028:b0:65b:2944:731a with SMTP id 006d021491bc7-65d0e9f3097mr2216857eaf.16.1766187394409;
        Fri, 19 Dec 2025 15:36:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZl/DHoSFyViFIRLj1UPlV1Kd31wcUI5wjcQyX+CRK6+g=="
Received: by 2002:a4a:e5c5:0:b0:657:59d0:735e with SMTP id 006d021491bc7-65b43986abals4346357eaf.2.-pod-prod-08-us;
 Fri, 19 Dec 2025 15:36:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXeDLXw8k1mZ98eGEphk1LW0aiggryLIXIN0s6odw4z0kKE0TUST5UxWdUKALakNWYpqGhqctSvrs=@googlegroups.com
X-Received: by 2002:a05:6830:264a:b0:7c5:3045:6c79 with SMTP id 46e09a7af769-7cc668bdd63mr2222727a34.1.1766187393507;
        Fri, 19 Dec 2025 15:36:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766187393; cv=none;
        d=google.com; s=arc-20240605;
        b=OU9/YirVSQWuP909zOblT8Fv9fTJSlpUxqPzVvgIr8LGv61YXKTrgnx+6ByzcVvoWH
         V/LvBnSTul24wGIxhhpwOwSxI2i1YMV6pkQZe4l3pixwEAJsnBPgi8eF/H4JBJcs/oje
         7KeghaujUh9ZVePcIb3vgOHF85ylbHC7dE+R3Tpj+Phy8ns0HCgLwkCjoLDH1RE/lVUS
         k9jxpdDWB02vtBHNp37BVlJfUFlEgPpDXsZwjxVir10rcR0MPwJYelHYEemHB1vYA1/h
         F2wnXEZLbL8GZVy1AHdyo5Llv58RaNhPY/3/v1CfDlxsNYbSbSM79ip/Uh+49wDL/xKd
         yxeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Xjhz9NvSIj1nkwStS3EsBbpnWvjG3hzX9yFNjSmaNpQ=;
        fh=Sc0+VHtX7tb0BcUOGmnyoy3mMfWR/ER/JUccSuNBKOs=;
        b=WtrZtZjxNYOsG+yCRpfuIUNf05PsF62klCwFliyyNQtlCq++HGKuPh2laBdfQQEx0V
         5+jGTAB3VWY1ubNXV5NMaxS6eF6p8U0Cal5fCdbm7pagk8+k/3rPGcrJgak3VziQgMNr
         ZOIyPUaJQByn8HTuubR5FtG+0a9mUatT3Vr85YK+pOXU26OMeFc9Sc/D8LTwTbOz3w2x
         71c6gk75KuyZP2r3QqwsG887FtHmiTB+96XZCA330qlkKk/J+TUGuGerCzIkUnZ9mVp2
         zykH65617jHJvp69iQ17dnd3ProR2DrH2ETYDxXFo5TyfRe/FuW3mdy5F8QGfhlkwlLh
         tsig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JybvMGKe;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667c988esi373383a34.5.2025.12.19.15.36.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 15:36:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id 41be03b00d2f7-c227206e6dcso180269a12.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 15:36:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVcuDjh3h982Q3xkkG78ME7q0jhxae5FhKSaquRt4N5uo0/7WiREc/GpNjxTHPwCXgSJlE5efVOJGw=@googlegroups.com
X-Gm-Gg: AY/fxX5vmjGN0WG+yd+dLMN44msJdYx6oBGllWzPHucO3y9AoRjumHjHxuxBYj21xv+
	RXJnAFNphXclbXVdZnp1eBIbWVI5zS/y9znrAWpiQm8OfU7aAFPkj130u0UrHqsK342uN+WaPJW
	hYfuUZsC7tRKh1iducdJuqtg8En8hxbth7BravVLOqNTpbMY9f4Y1n8tOwoZkY9OZY5GMi8Data
	SjS7EHijGKcbjmNO4VJDMg1ewvTR3/DpukRiTcIr69nmsojapQBgAYjzxLjSLgegNPwYeF5pj0M
	LiPndqRhmvnsYDvoFfAGy6nMBmN5C50EsVHXT44sVgNAcWcMtr5DDQVCpPjKpGiQ3CyYIaLDs1l
	DG51QQTPWYm0VjiushJ0x4V3IG8keS2Qmu1Or6EALTxBX8xXGJoE709HOGyAqL7aD583matI4Dk
	zpuCzcoveVUuRne0M/+hdF/rEPTY+8zW39R3XSfRVGVkgsIuRdZvpQXamEVkOKT0YFvk8kgBK3b
	Eu6rUkEApdOndQtZey0lZIosDvXCkEP7b3JweNCvNwnyJflsl8baJe03Rc9sPKsAEu8FJtwZDjz
	uYs=
X-Received: by 2002:a05:7022:3a83:b0:11c:b397:2657 with SMTP id a92af1059eb24-121722be81emr4954809c88.22.1766180747284;
        Fri, 19 Dec 2025 13:45:47 -0800 (PST)
Received: from ?IPV6:2a00:79e0:2e7c:8:5874:79f3:80da:a7a3? ([2a00:79e0:2e7c:8:5874:79f3:80da:a7a3])
        by smtp.gmail.com with ESMTPSA id 5a478bee46e88-2b05fe99410sm10260116eec.2.2025.12.19.13.45.45
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:45:46 -0800 (PST)
Message-ID: <ae957ee5-cb47-433f-b0b3-f4ac8ec7116b@gmail.com>
Date: Fri, 19 Dec 2025 14:45:45 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
From: Bart Van Assche <bart.vanassche@gmail.com>
Subject: Re: [PATCH v5 08/36] locking/rwlock, spinlock: Support Clang's
 context analysis
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>,
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
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-9-elver@google.com>
 <17723ae6-9611-4731-905c-60dab9fb7102@acm.org>
 <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
Content-Language: en-US
In-Reply-To: <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bart.vanassche@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JybvMGKe;       spf=pass
 (google.com: domain of bart.vanassche@gmail.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On 12/19/25 1:02 PM, Marco Elver wrote:
> On Fri, 19 Dec 2025 at 21:26, Bart Van Assche <bvanassche@acm.org> wrote:
>> On 12/19/25 7:39 AM, Marco Elver wrote:
>>> - extern void do_raw_read_lock(rwlock_t *lock) __acquires(lock);
>>> + extern void do_raw_read_lock(rwlock_t *lock) __acquires_shared(lock);
>>
>> Given the "one change per patch" rule, shouldn't the annotation fixes
>> for rwlock operations be moved into a separate patch?
>>
>>> -typedef struct {
>>> +context_lock_struct(rwlock) {
>>>        arch_rwlock_t raw_lock;
>>>    #ifdef CONFIG_DEBUG_SPINLOCK
>>>        unsigned int magic, owner_cpu;
>>> @@ -31,7 +31,8 @@ typedef struct {
>>>    #ifdef CONFIG_DEBUG_LOCK_ALLOC
>>>        struct lockdep_map dep_map;
>>>    #endif
>>> -} rwlock_t;
>>> +};
>>> +typedef struct rwlock rwlock_t;
>>
>> This change introduces a new globally visible "struct rwlock". Although
>> I haven't found any existing "struct rwlock" definitions, maybe it's a
>> good idea to use a more unique name instead.
> 
> This doesn't actually introduce a new globally visible "struct
> rwlock", it's already the case before.
> An inlined struct definition in a typedef is available by its struct
> name, so this is not introducing a new name
> (https://godbolt.org/z/Y1jf66e1M).

Please take another look. The godbolt example follows the pattern
"typedef struct name { ... } name_t;". The "name" part is missing from
the rwlock_t definition. This is why I wrote that the above code
introduces a new global struct name.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ae957ee5-cb47-433f-b0b3-f4ac8ec7116b%40gmail.com.
