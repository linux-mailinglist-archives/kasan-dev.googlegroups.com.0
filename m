Return-Path: <kasan-dev+bncBCSL7B6LWYHBBTX5VDFQMGQETZ7MONQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EEC75D31EB9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:36:15 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4779ecc3cc8sf12856365e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:36:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570575; cv=pass;
        d=google.com; s=arc-20240605;
        b=EMvbQNUCiqgLRyQMxtOSE9f/prdlUkOvOJPkK9UJPiwzKBl0kpAFhAd6DpWs3mrpKI
         nw0OtcuWv8aLZ5j/DPB4hgT21AINs3wfrlo2LXXCHkNkpMrvhK1scJlv/XXQQ4jn4JdG
         GLZftjUWz3sUxsgZLEVM5HR5ZAVVo01Il99OJaKfrbNU3hn4ic0sZmxIjb2mYAaHAxbF
         w21DDc5ZdQ2kc+XiCRqvvGMkzkh8oFuPfehEMcDEVUSbK6Q9t9y41H8a/kmderr69ezw
         II5xFzegoIOutIew67EAVfKCbXXIbwWnDf1c0g9cvM+TSAxUCt4jheq0oQ784RCH53j4
         a5Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=A5MXSprCud07rd6vUZMRVV9SnwWzGvHASF8LNLUe+V8=;
        fh=EWCeAgnABwYQfNO4/IMv7gwoIlLm7cQj70hBfTFvdvk=;
        b=ccxGvuzfb76tKCYDUxPjqVQ2bMvbu923ALt77UF0ZJN7XMsIJcouiLZhw2KDCLgsOu
         R5TUr5Empw/wxr72hBe+1HAPNChpnJTAfjzWMYWRt2wuzNgfaVFV9quMLvm2bQXa80uG
         AXe6MZhChd+1BkTEQ1OgOG7Bgg53neT/v2e2leM4+PWJm1GZm5hKeWaUzsULbWSrDs9r
         /wiHN04v3LJqv9aAn+27iQ4we5ZMdRkyMl9Vt9D8JPsHPhunb0FUFWJQN5hiDYHB3gE5
         2uSJhW471wJRzpO9BelsgGxIN7KAb7Wpex6ZmV0e6QCIQdU3HxWh76Ni4roUrFuR9+Gy
         zgTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KnT8uD8a;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570575; x=1769175375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A5MXSprCud07rd6vUZMRVV9SnwWzGvHASF8LNLUe+V8=;
        b=nQfX2plYO1WHvRdBw1m87bX44rM9+j1atgBlbNUna45p03RPHJkK0EoZl6XkTuYkDe
         1ieHyhZFKyu9hLnhduR4ULul70A/vkosW6O1DOwSsoo86JrbcwCLRr4nVpebKDhrU31B
         6D3Otq15C9HlsbGYw69tEytRBxN2PMXelHzVdJflr7KsssprEQ+pUlH7PVW28mxJmOkQ
         sV0jIWNIXvlZEURPCL0jdKJBpmE15uscGxG1c5oK7/cacJOEZDUeUj7ezwVoDIlCOtAN
         QCPnNZTQeXpd501Up0Qos2ydkumIWP4Yxe5oVH1vMJAC2/82szlzZ/Eipn431/QZt5m/
         8IwA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570575; x=1769175375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A5MXSprCud07rd6vUZMRVV9SnwWzGvHASF8LNLUe+V8=;
        b=gR0sLKXNtDhzFH6MG+HMdPfj7h7W75DsNjH3rLij8YVCm+cVJIEjb/in+Ac5eHrAXj
         UkogU/ibcAdhkq9l2pLqY0jdtfmvYu/V7DLda4TsREduztUhAOIx28cNq8zROu9lDxUE
         b8UgknXSeScBK1mnirEHQvl9Vcn60O8vS2kCn3XTBr0q8BxVJIuO6lS2svZyraC3Icm1
         ULeqkYCo0dY0zJIKjblg0OOq3/sPYxHvjmHszBV64EC/81dMXgAPyuz6U3/cK07boOCy
         u2JilNZgDWfSTjkC77/I8PqzBR9Rb2erPgE50JxDtpzjz012M9gp5AT07KddtTTgeKKD
         cFRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570575; x=1769175375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A5MXSprCud07rd6vUZMRVV9SnwWzGvHASF8LNLUe+V8=;
        b=L0SUSqfJZfPq8fd40jvXTUp6lI79DQdsI35KqBycFmFHBY1eD2Oa4WOHCY4V5bjcbe
         +BmhA8Ht3denwa4/JOyor6H0gU/N0sXED6cM/5sYTwFjJAgRoLKIwwK3Rk2eJ2UeXOsr
         an5vPLN9IrRbLyl/Tu9HaU1VEPZKMHWRoAheXQbS4YZeFLp4ZMZ6exCijPo241PwYwVV
         Ilmwm120sK8ANLdJFXLr1ffJlOaoKuYUYjYviXhGE9MLxc0NHzSqcCoyM9jRk7lPdjEE
         THMtip75ntDPQPxIUNM1knvkus0FhGZMThdHkj4OOi6BPIPY7r0BZiI/QHk9tp7loQzD
         todw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6hKDOB75c3kMJyy9+SNueVBu3a/aG0QQQDLKUQWWkJzmV051fAh1gxsgBAXeP+Js6bsBJvg==@lfdr.de
X-Gm-Message-State: AOJu0YyjjTQgfqryRNpFjTMELd4pjLAn7VlyNwCBF9IcDfPD1pwQcl8v
	zY7+V2gYWOkuyJbcwm6Qch4A/RBHEE4LzDRQqdBCfubFjoKgFR2NDBkj
X-Received: by 2002:a05:600c:45d5:b0:47e:e57d:404 with SMTP id 5b1f17b1804b1-4801e30b8a6mr39835065e9.16.1768570575100;
        Fri, 16 Jan 2026 05:36:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Evx0vRWOq8+vsHrb4/uNrjg1j6FURpckN6Ip8hJbAj4A=="
Received: by 2002:a05:600c:1c02:b0:47e:e788:97d2 with SMTP id
 5b1f17b1804b1-47f1a8dfb4fls16034475e9.0.-pod-prod-07-eu; Fri, 16 Jan 2026
 05:36:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXa1svwyca4VQI3nT88vNFV18QIIwEDx9WMwtpulJGwZJXlt+CRwYgyNwQ8C2tO9midMUUnwt8YjFw=@googlegroups.com
X-Received: by 2002:a05:600c:628c:b0:47d:403e:9cd5 with SMTP id 5b1f17b1804b1-4801e30b6ffmr31329525e9.11.1768570572390;
        Fri, 16 Jan 2026 05:36:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570572; cv=none;
        d=google.com; s=arc-20240605;
        b=ZzKSlB/BzaWyPkArHXoD5bYXqO+IzOSMuJRbVbRzqsqabCPtGJRvvSiFvnjpIP9GFn
         ZsHCZwNQwuBnMP2WB8xjiHD9MiwZKa72yGznTicz4gOOSPxDlh7sXZmS/0XTCFUErnDj
         DGgN88JaHtQmXc01WaKe4pbhX7Wt+APGvYzcietx7bunzsYyN1I6HfHAa4hbjkhlGm/p
         9XKuyQPHpUjIuCDV0mce6C5h5rydG3tUz+P3OyOhYyhq9dFJBVEtwrfxAraj3/gv7TdF
         tytPd9jZwuiLnlQkYTpmSajbhlZSRCnBZ/9MRG86668HaqHMWMOCeon6gBfEkz6YGwna
         4igQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=fMOjuo+sGduAgoZx+VCdetEtL8RwS69nkBaJxVuZUv0=;
        fh=gX7oR+AU2f9anDb4Zh3Lzt0cZhqvEQaPbZju5PeUwT8=;
        b=I7oJS3IhoYc54w0qsKyDbQ5+pcBpfFgbOntF+yjvnDQn53g7OEogPHIgSfbts3aIR/
         mXhtTEa23W1HCswff4vKlYM7vVy3Xugc0aHvbRfgLeXRxBJDQ1mvF6dDydsAvdBK9Yoi
         lvCLQefIPOn/2fd1BXxZfyJE8bgSXXnZoxKo59IdtAy1fnHZ/EMnHMkL8lbu4Vf/pgiV
         DoelFbrwFcnV/zysTZvGrDPhSgRxkCC4va42cuAacLzYkW/RIgorK3bws2hTPXE/lQJY
         ZuL5wRcjwS4JMA3n6iF+6cPCo5e5yp3lNDa4B+CtLGIXFk7OtQ6Tomk+8hYexgillUgO
         7QPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KnT8uD8a;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4801e94368bsi140815e9.0.2026.01.16.05.36.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:36:12 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-59b717b0f80so205892e87.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:36:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU54rha/Xd8ydk12KDBpXpZ1LPQbGDWfbnzv9xP7TO62rwhhM4MmIn2rAk6sMQqGDE+fPBg3IkCYBw=@googlegroups.com
X-Gm-Gg: AY/fxX7yddBGmN0g8/iqvnul1SabF71vU1PE150k1nNWrL2YbJva018oJW1OrqdliqJ
	INrWttiztxRSuaW+5cVegukgNSh/jPAsA+k69lPmCNLl/9MQVzWNntj+nmYDaGLcS2D1+kUktu9
	Q+/uqXTTLGurX/HjLpIy/W5x8DO33LPxrRh8EWw9SS0Xr/NJTxaPWlXlxUICOwTPmZv536weEpr
	wyTAwgUUl9ssEp+fKjMNu4Pd1rOm9t3wHTmFVKSo1A39S4MScaNJUoKkOlUOglKO0J6ThEQiptP
	w1fa3m2v+RHk5u+J9e6egpcfTN3r3VP4srqjwAIyDYNX32+OQPtUcsgezGuDCMg2yeWP12O6SJP
	5Pr7O+aeX+cL286GaPCtU5b6/tXNrMS4A0zcXrV3RCvjbR0ygYPmSBPBSxAtzdCTGKK9y3uojHD
	cE9wQWvAocRCELYz0nXg==
X-Received: by 2002:a05:6512:3515:b0:59a:10c1:8f27 with SMTP id 2adb3069b0e04-59baef10857mr597870e87.6.1768570571302;
        Fri, 16 Jan 2026 05:36:11 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf3543d2sm770392e87.43.2026.01.16.05.36.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:36:10 -0800 (PST)
Message-ID: <901fa77a-b23d-4268-81aa-fc76846ac73b@gmail.com>
Date: Fri, 16 Jan 2026 14:35:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 04/14] x86/kasan: Add arch specific kasan functions
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@kernel.org>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>,
 Wei Xu <weixugc@google.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KnT8uD8a;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 1/12/26 6:27 PM, Maciej Wieczor-Retman wrote:
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> 
> KASAN's software tag-based mode needs multiple macros/functions to
> handle tag and pointer interactions - to set, retrieve and reset tags
> from the top bits of a pointer.
> 
> Mimic functions currently used by arm64 but change the tag's position to
> bits [60:57] in the pointer.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/901fa77a-b23d-4268-81aa-fc76846ac73b%40gmail.com.
