Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3WHXLXAKGQEZWLLPNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id BCEE9FDE9B
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 14:11:11 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id d8sf2259204uan.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 05:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573823470; cv=pass;
        d=google.com; s=arc-20160816;
        b=YHFlSBC0geoERi+eoZhY5gRtfAbdnVzfuhfk3RgRrilJhLcz1vB6ErWFCZBO4Cfq8T
         OzN9/D561UrKF3292WqoMXvrhSMZhXlK7oA4CMFbDql8FjW5aFDVz18bypcdOXpnHOvU
         Bl6kYRYEY+NMLzUke6ztX89P2onhi7sPiJUQXtAxO3CyOXAQZ6TrBb0R1RfPdporLM7g
         0md6EtU6g1aI1S8LWYq/ok7wSRjENysyQPn+uKpmlQxvj3di+gKi6vpNmF0alw/LB9uh
         vHi+0tIK9dVd3+zjmLymIR+gN5X+wt8l5Q4Ng5VtvRWlPtt/PjJiw2W93nBPihvcherD
         sxgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=5JPpCIOo0KfIW6s5GUq0LGhvnFMJ6iLHXBkASMLrtt0=;
        b=RjZv95AvBgbHwnLgOBvZNDilMRL5xCZ+lxf3c1ezv+6zGscd37b5LZSzav1WOM3SQ5
         A1HAe7ivzDfS6GTPxpTBqTKPTqmDO+yDpCYOFEtDmHd0YghBQRbvR4KjIhpCDGZgyysU
         y0MWg24UXJKHEHUKmZyOXgZVr0t9vFnq5AhBhXjvXWQPSBTucxeNJVgR18VUnJmPyu8n
         3zwBwnMmj5+a4gC+hFwm3l7o0179TW8yf7kUT9Jubs9fH6QS3vBfoBZoPbgLcfeB3w3t
         7Bc5TbMXpP15KLK8nS2llmtV6KspoATMO6cpJNId/hfuSFyU3AoJ5bskb4iodCPz/j6j
         5+6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Jn5lFI/f";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5JPpCIOo0KfIW6s5GUq0LGhvnFMJ6iLHXBkASMLrtt0=;
        b=DJN/jpQKWd+UAAgZ5NFRHZRJJMcrryhJeDSkjYeqcQuLJTAJRAi9AG3e8e2RjNgcFH
         ujBHBSW7kFV99Y0KjUodOTpfTkfBReWHKRQ69hlyzn5t2fsYrPE1SmaShHOwXNPEzPxD
         /E4gL65c3fu6BUcJd66TsTRyvIXJr929uya2Oe19VJBsaevG/Db2OQmCCeoME6XsKlGk
         Cy/HS/PQzTHhC+1dj9oDXW0mklnJqABkfsNIKJIgTViC5K2XNYRiSnHbh2NUtXGuCPD/
         KnR0Xp1Atz2kVTRVZWg01f2YjT5fZ2QFs3JUZYG4iHh+9IK5kDGgxsuBvV7blgL+SAsa
         QUbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5JPpCIOo0KfIW6s5GUq0LGhvnFMJ6iLHXBkASMLrtt0=;
        b=lY2B8uf/7eAdtUe7klpxOdEw44yWbgrRY1PRzTc1jY+pi0eQVFu6bFDtcH9T5ZPxXy
         ggQvEvCTBA5CuImQRMqXvtJKuzApVVBsgo4BsfSy2ABjDaHFKgyVVeOUoNAdfHvmlMzI
         5Ded6rWd5ZTXuPOVfle8Oj9SVrRRcXAM85MJ0YJf6zBnQ4ep/17FGzFEzA4x8Vku7lVi
         nSfRplEyO6/jvLJXw4Q9AE0pa0Q5xLNqD2WS9uQJbh+cIlGp9XG0BhNVDQPeSQHeBIOC
         L+9sozhGSGcnL1J5XxCe/zfVoHTA7tJA+2px3CJTYTy3+eksHK7eIuopA8wIz6Kck4K2
         16/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWCA64rxXebQYc7FUdBp5htxOr6eXpBizZ4U/ar7UKHVwDrtvdF
	CXSapqCgkB79Rm5yPfSCEEM=
X-Google-Smtp-Source: APXvYqzbEPJUXZdvZolfzkarK5PL+z9kQ0+zEQfeEwxwF1D2J/1Z0JQqoruIEqo9bfObGgZ1EaXkJQ==
X-Received: by 2002:ab0:314a:: with SMTP id e10mr8728429uam.98.1573823470499;
        Fri, 15 Nov 2019 05:11:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:54d6:: with SMTP id q22ls321174uaa.1.gmail; Fri, 15 Nov
 2019 05:11:10 -0800 (PST)
X-Received: by 2002:ab0:598a:: with SMTP id g10mr8909243uad.74.1573823469998;
        Fri, 15 Nov 2019 05:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573823469; cv=none;
        d=google.com; s=arc-20160816;
        b=egSH4K3H0WMYzlMpi3brcN83CZzMSFo3hoX0knYxNXPiWE6wHGWVl7aRXPfwi4GNX2
         L2SXnmtVHT+OWq2BAI+8/xkjb292XuIwErb2ccjalYWVezFVjY8wBh+YTBS8e1F++OBt
         Z0TpZKqtHuIqrCdNFxpyXyaYbuDWizdqsBLyrdWt3NIsb5M2VRkFq5Pm4DmKCNO6UkJD
         ljfY2UoofiKczjXEQAGSEJutDZP4it+V1oDG11hL/i2Uayw40xGWJjFQn+ko9iZb3lKM
         VMCK+0mVUpVEFfS1NbMxcl9keiyBjTI0a1d8XajLwo6ttvaxtbaXdQafvwPibqunQ+pJ
         vlxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=VdF8MMu+bP4e0rsVfdQpCfgpPGQbFW5Ll/rpGu4Pq10=;
        b=pESL1YAY+OByxGeyGN3H4LgxcPRYWmamxJ7rwbO4+wywDpAQNBw5p5ePMTbpAz5MmS
         Yjma05IJF+rbQPhKvHFjV/rJykvI2PI58JGLYRZKMzsBHKRw8R++yHVrSjePuMcPMvxK
         2Ahj2dxks9wJTqDKlpPZuW5n/hEYZGZWGOF8uAN5tpUgsOfKkWQNwNM6sjgPPLO0Uw/g
         M7vJW3Nna+B9X/eQUrntSA3fu2j9nkmqB4TJCSpTYijh55yAgxRMn9asXo/Uwmlig1dZ
         PyEX90AXaWbGjByEQac7l1dNfTvCUYmzm9OD+4Nkb+VCpuvulF+7hIF7f1NL6paiv8gE
         cl4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Jn5lFI/f";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id p195si610721vkp.1.2019.11.15.05.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 05:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id f19so5990016pgk.11
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 05:11:09 -0800 (PST)
X-Received: by 2002:a62:6044:: with SMTP id u65mr17331024pfb.227.1573823468977;
        Fri, 15 Nov 2019 05:11:08 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1d8-c2a6-5354-14d8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1d8:c2a6:5354:14d8])
        by smtp.gmail.com with ESMTPSA id y16sm11164122pfo.62.2019.11.15.05.11.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Nov 2019 05:11:07 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>
Cc: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch <linux-arch@vger.kernel.org>, the arch/x86 maintainers <x86@kernel.org>, linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com>
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net> <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com>
Date: Sat, 16 Nov 2019 00:11:03 +1100
Message-ID: <87a78xgu8o.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="Jn5lFI/f";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

> test_bit() is an atomic bitop. I assume it was meant to be in
> instrumented-atomic.h?

Hmm, interesting.

I was tricked by the generic version doing just a simple read, with only
a volatile attribute to ensure the read occurs more-or-less as written:

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
        return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

But the docs do seem to indicate that it's atomic (for whatever that
means for a single read operation?), so you are right, it should live in
instrumented-atomic.h.

Sadly, only x86 and s390 specify an arch_test_bit, which will make moving it
into instumented-atomic.h break powerpc :(

I'll have a crack at something next week, probably with a similar trick
to arch_clear_bit_unlock_is_negative_byte.

Regards,
Daniel


>
> Thanks,
> -- Marco
>
>> >> +
>> >> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
>> >> --
>> >> 2.20.1
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878sp57z44.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a78xgu8o.fsf%40dja-thinkpad.axtens.net.
