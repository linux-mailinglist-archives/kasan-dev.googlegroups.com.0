Return-Path: <kasan-dev+bncBCS37NMQ3YHBBT6T5P4QKGQEHY5DNQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 407F3247829
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 22:34:24 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id z1sf7442172wrn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 13:34:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597696464; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6ANuFT8CSo7zMOchIpjBRc5IEZv3l81EZsgwMDstM8pMQs5hDDcMis2KgUiWV4TZA
         DleqQ3BjXnk8HN1XA0qURqnjlSCoEkzxdcfnyE23enDvbKuEzIz9Qtv7e3jVbYM8v4N4
         toai3KblKcDiGhHHUv+k3c50tXzrYO4a3j2ou+5qibht/sniZfHmp/Sbz/821Y58Uz6E
         80EyJ8n3rlaNXTFxOlxFijlfQXof0K5hUvtwK73ZzR4zDYQVf0kf31AlrgcXKWpnFjhy
         T7XP+LCjm5iQDV5Lz7QXjg9c1wAXLS3zcPMESuO1dkZ2hpTj+yywa+yQrqR5D3Gakn42
         b0Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=V4Ho/Bfq0ph0hUUauOdo2pV9aqOcqUx9EGClkhTofdk=;
        b=WR1m5w0zc5sBwYizOGC87/oNoReRDK3zPk4noT1NimbehQK8uIRopMnq0Vpipuiqfq
         8dIQH8fgmjDTVAkWItD09nN8aUk0FLM1/+IA8IAb4bDTC1MY7j5mUdAqplS8nUyqkvd3
         +05CYkja3sSPbsaNFi7vdCwmp7C3FziV4Qem9UjL69l5NfayAxP3jqLGaol0N9r7yqpv
         fqfDJI7jaNyF/9kh2hwUCqLQr9Y9DgRxEyGW1OeX+nOaYXurVKRtVtVGD5MrQuCTPx3Z
         mZj0rKgZDIlFlkGTDOSNudSK7O9UPK92zrIdihK0M5aB5NodaEnqKp+uh9ZPpGvYkcwm
         KYRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V4Ho/Bfq0ph0hUUauOdo2pV9aqOcqUx9EGClkhTofdk=;
        b=Bu58XhqupvRi90Cck2iXCEAVgEnXbnjGmS/W8X/vHSQewPJYUZaJ+udbthtwX56nUE
         Fl4M074MjdLZQwcXsLos2nnB2BR98oMCcH1W/tTjC6leR6nAhfNjnzPfp6og2YerBGj2
         xq2m78pp0diLek5cMSSV9SJ/LfPqNBJDon+oOWvAEvJq99ir70pKxLeHTi+bcwGbllzi
         Z2uRJonOUDVf0ZbYT7cxbw9z5vSW+dUhR/j9gymZyvs3ZgApYuW4DYeQHaJ7w7AWsY98
         NCaHd05o3qU71RSKmjNMENxdclQnGRyuHJuqhrKKKtvr/VaYJD3TqVA+WGaXdKNKBfH4
         On/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V4Ho/Bfq0ph0hUUauOdo2pV9aqOcqUx9EGClkhTofdk=;
        b=RpwQYh5SSvaxa0LOPTf/NyGSpECIQ52dR0elJLVCSXNYo3K58S+u6zv2pVPMkIoQcU
         0gvVshjS2LGQZgiw2k47BVa9Hw5LhAJLNK+V3V+Yi7SIEjSA8z5Wgdyn4XBotipFji1I
         4cebFw9BK662djbRIS+LJNFey9oh1qCqSS65309KgnJduJV+YiEG1tceSK64WCTV+r3E
         4BIypzGDuaNZ5/5cuDM1SWPxIOSECnVkGg2SJQq0H2crjJR9cohw9W4bkwKttm7qRDml
         pP4Vbyr+Hu5Tz8y911LXVzhj/0ReI8DJJmeJqARj8NUSgYYSgbb+WNUf5hON+LjhYyPS
         nWdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LMaF85uPRsYUyFhhg50RSf7OonI/dGeJJSrU+r17BcizE/4bU
	lqdtyZzQOE0VGQVTTcb61tg=
X-Google-Smtp-Source: ABdhPJznZrdA/tL1gUSmKrLQtrsosOGRKw4EuWwUWsTYAsS9stbj1dh67hNZlB+bTWN48fZJW3RFdQ==
X-Received: by 2002:a7b:c20a:: with SMTP id x10mr17306316wmi.177.1597696463968;
        Mon, 17 Aug 2020 13:34:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa8e:: with SMTP id h14ls148427wrr.0.gmail; Mon, 17 Aug
 2020 13:34:23 -0700 (PDT)
X-Received: by 2002:adf:f606:: with SMTP id t6mr18012101wrp.182.1597696463309;
        Mon, 17 Aug 2020 13:34:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597696463; cv=none;
        d=google.com; s=arc-20160816;
        b=P1Ha9s4wtCFpH1WhUn9A0dGLzxwDhCaY66OOkvU2nxCcUMCfZN2h92P4H1OzzSS68a
         1dPb8d5FuV3/zGfPcrM1LFM4zJrqHcvNeJ136KnPcmVqKLA1aNSfD8KQ3aiFEAxI9bNY
         At5Xz3+zyzJ2Ziz3hHrKro3EnDyXrXOqqNHSu9WuhUP4wAR7fp4u7bo4Sns7SglVm5eZ
         6aS7hVx3Enjg2O1syRaOjIus1mfktipiBV6IniEEIvu3xAe3EF8AIuK8wPvC7CMeST/s
         ikqvjkjNBKVVZaI1rUS6NoAw5QhIq3giDuVm0Hra3NxSYVUCBr8mug0GoRts/dV+2IMi
         JAWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=HMmAhojE6Pi6/w43OvxPWGnWTk1gFOr4fwGmxJ352yw=;
        b=TtXHgQkmBK9HcZzsa+TY3v5S0aBftGvADD9X+dUQvJAqrdttVHah1pXKCiYKQ+nbv9
         wr3NqvJLxunCn4xOf43ONE1y36jW3Z5MiFkYAxDrBcIWa4SpMxjXYlHUiPWKFyVZeavV
         3ujCqpKeStJha0nwm588Xw4fv64batPD2IUUtPnIrOF//6nxfWeHNtv+BU2hEUl3Odd6
         RuM7WLrBE/Rtv+Uwe4k9bC6urmX3e8w7asSNKUtDaXIA9d961h90AMHBlD+mLwRuHJsh
         X/XBnl7/+Z3Y987GRp0BPpISn636Lv3w9j1SJfkXhV5bAngB48VPJPN9LzChwlDnSF4d
         VOoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f66.google.com (mail-wm1-f66.google.com. [209.85.128.66])
        by gmr-mx.google.com with ESMTPS id j83si7305wmj.0.2020.08.17.13.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 13:34:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) client-ip=209.85.128.66;
Received: by mail-wm1-f66.google.com with SMTP id k20so14985184wmi.5
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 13:34:23 -0700 (PDT)
X-Received: by 2002:a1c:2dcb:: with SMTP id t194mr15547368wmt.94.1597696463026;
        Mon, 17 Aug 2020 13:34:23 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id r11sm31238821wrw.78.2020.08.17.13.34.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 13:34:21 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Matthew Wilcox <willy@infradead.org>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org, notify@kernel.org
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
 <20200815185455.GB17456@casper.infradead.org>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <27cbe7f6-d372-f36c-d346-deb19b2cf39d@linux.com>
Date: Mon, 17 Aug 2020 23:34:17 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200815185455.GB17456@casper.infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

On 15.08.2020 21:54, Matthew Wilcox wrote:
> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
>> +config SLAB_QUARANTINE
>> +	bool "Enable slab freelist quarantine"
>> +	depends on !KASAN && (SLAB || SLUB)
>> +	help
>> +	  Enable slab freelist quarantine to break heap spraying technique
>> +	  used for exploiting use-after-free vulnerabilities in the kernel
>> +	  code. If this feature is enabled, freed allocations are stored
>> +	  in the quarantine and can't be instantly reallocated and
>> +	  overwritten by the exploit performing heap spraying.
>> +	  This feature is a part of KASAN functionality.
> 
> After this patch, it isn't part of KASAN any more ;-)

Ok, I'll change that to "this feature is used by KASAN" :)

> The way this is written is a bit too low level.  Let's write it in terms
> that people who don't know the guts of the slab allocator or security
> terminology can understand:
> 
> 	  Delay reuse of freed slab objects.  This makes some security
> 	  exploits harder to execute.  It reduces performance slightly
> 	  as objects will be cache cold by the time they are reallocated,
> 	  and it costs a small amount of memory.
> 
> (feel free to edit this)

Ok, I see.
I'll start from high-level description and add low-level details at the end.

>> +struct qlist_node {
>> +	struct qlist_node *next;
>> +};
> 
> I appreciate this isn't new, but why do we have a new singly-linked-list
> abstraction being defined in this code?

I don't know for sure.
I suppose it is caused by SLAB/SLUB freelist implementation details (qlist_node
in kasan_free_meta is also used for the allocator freelist).

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27cbe7f6-d372-f36c-d346-deb19b2cf39d%40linux.com.
