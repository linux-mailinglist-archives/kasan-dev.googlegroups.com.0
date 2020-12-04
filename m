Return-Path: <kasan-dev+bncBCS37NMQ3YHBB6OGVD7AKGQEDDQJB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 04E1D2CED99
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 12:54:34 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id dh21sf1411625edb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 03:54:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607082873; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ao5bmzysPgVpdHZadMoBqxTGntRtbvZuP5yhWD110voKFjW9ZLSDv0Qh8aO7FvBeuh
         dW+L46iKx/mKu9nWU1Ibt79K1oHncw33oNHjIlZ7APARbgJx43Ixil+lCBXwbcSBJEfB
         Xj1LW8w4+qn9cPvQFm6egRV6TlDuB+uNg+r/sHZdhiDLgUH7pIkgynHOQs1zEcdvVphq
         y0yci6i4eiBp75+5zs3D0vrcu4ByA0vmB9nakFy2ueuRhyFWo07gxXnXK3zcqZ+JmEn3
         DKclNJO10HePhimz6FxUhc2oThRv/V7s0fpZtC6/RDNuQv9B6fel9qLDDS85RE4dSiSu
         qQ0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:reply-to:sender:dkim-signature;
        bh=6VqPAEDSq1QZHWs1OLm6V3L4/d1WAkWsYPpZbUXzVWY=;
        b=nVmiKCemKXtMpZAu180qoCRDHyuZ2NSaIT2exTkh7tpjSjhlIOgxUDPjhf0f1Greic
         YIhSAgpF9Gqump59t9CpEb04IYgyGN9Y1QMdj2tDb84caUW0l0uMdLbaIcdVuil1eQKc
         4pp6eNQOs0VzfSDL/7zChTPVLHjTevIqhKtQzG5YMQrSCZXUC/8avRD7WU97QgJV46pK
         fpjEJSoLbhtvnowFrpDoXVgwc5AhDDOj7OBFb1Wp+oRSOmYGZCuYhx2/T+S2VI+Gygag
         SeqPtjYIzlAShymIxEHIVKTdNcJZRR8m6r9Z46ToMQdAMmhTQwC+9pAWkvdVqy7zHVpA
         nxug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6VqPAEDSq1QZHWs1OLm6V3L4/d1WAkWsYPpZbUXzVWY=;
        b=Bl5A21/8sGn+3Tg2hoX5Icm/1e8FRy84DgADzJ/Cwj/pXO+ANVlhyvuJhdcTMOrOYZ
         YxoXfoQxhytB/Nt613OxcaKZlSSNL2qLAitPzpC+7kV32rJp/whkYt2fECvSClzLvaGO
         pH529WFvkMLQ5vQQA+b2L2hrfRt1ZPByhunPbJrs+muWHvjOkUPi33lSxSP3+ZiakM1N
         TH+5dVuJHveEfkeG9aLVItafIsdOLj5j2jdt/eCOC7vBbQukKtE1qQLUCiv9ES6jafk7
         0G0kHPbmHLpDTw9QSqqcfRDvklT2OpSPr2S8Hz8LsL2HI5JJ/Xc0W6o4XWUj9ISlTRCd
         6Khw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6VqPAEDSq1QZHWs1OLm6V3L4/d1WAkWsYPpZbUXzVWY=;
        b=sx4860USmw1B9GUYBYDGk9B4TcpdKccu92Aj1zkLbu8Hz+uTiyKdgM38YsKmm46NwB
         8VzRywiaxGAThzSJP+NwK5p6IoZdisCkm39/xSGftWUSyuoS7AUQ+VpmMV/T/GjPnt/N
         QfeMSCMawXIt2ApPmabUgHk7kBA33mmjyaeejxuCxcgEwaXFVWbkK3L6cnbo1ZzPcEoQ
         gp9Hd9AnwLLK0a+r5biK/g8zbBZr9fl8kzrRMZ/lOt0VX+BPQXT701MqKGo4GDfCAYM3
         d2i/b4f1DOdPgKhMmBIrb7pSN/G+HWbCvbeuuDI1xcnZFOTNWpRdS5u3eSQFopetvPto
         WBZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316wh8+hw3KYStOSqono5Tv1UsTxxc8vYJYDswcnrXmwJu1ASj4
	/0zHq63aIQZrWoafq6YDWV0=
X-Google-Smtp-Source: ABdhPJxZ+SohqfDiSfGYUY36t/pIvUgSQT8oDnGnDYnFMwaXYuWprcHmHoX1hixiNoWIGtqhnacj5A==
X-Received: by 2002:a50:e0ce:: with SMTP id j14mr7254142edl.18.1607082873807;
        Fri, 04 Dec 2020 03:54:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls4851739edx.0.gmail; Fri,
 04 Dec 2020 03:54:32 -0800 (PST)
X-Received: by 2002:a50:b761:: with SMTP id g88mr7209085ede.387.1607082872925;
        Fri, 04 Dec 2020 03:54:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607082872; cv=none;
        d=google.com; s=arc-20160816;
        b=NtAVHSkAtpP/hAkHZTmFI9l4u3e4v0mKQj/Cg22+HZ5o7bGRKdgSyYdhwLWXMsG4HZ
         JGTyatAgOXV3zJUY+hwXrYL9gFjCWDBT9mycUCR4pBGNHkbPdAs7JZQBaXRuDxwNQ1NA
         rmiFDCJdzDeQjkx8qBfcGrdrbDuaZ7IUqaLNoTFi9MtxK5FsxHJYfvKZdp/Cp9cDH7VR
         mClTKbSn/rg80U/kmcUHcj1J/bU0YSvoCxGIfUyna5LJKu+tU6Q6jubMnCg7rV6TztNv
         Y/ra+supA9bNm6cIzz03QVLN8X49T13x9s/P71lDqtbY9Es+i6ii1q36F5ujvCtvfxaz
         gSXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject:reply-to;
        bh=wHqmBeW2IFxVt4oHJizfcV3fQQX4Hgdaz39Wp4K7c0A=;
        b=CXE4v9M7XPJ8SwCJQnK2j+sYoyj7TNl+uvvlfEifcpA9/udLYoWVdQaN5I2cbseJn8
         8cFu/dzcdp6Ym0s6+DjFpDdapfknzWXk/SKd7CMieVDQyJJNX+G0qug1NMq/b2YsroPv
         ZUDXXs7QBjxTzWT4dfIH5FcF2SGrA4gQMF+vDEkZ1dbB9jmmNoFs6G+kMWn73hLZkNI4
         DqSVW9HJmbUdZjTxzZfNgI8dZaZPsYfgNQ4dZBryKVtodU5ucweaIZiib1W504ucK+Ni
         oQ3AwH7qjIdyCOUkHkEA7HMzyOU+M0QPsguw2/r9x5i/X8DnZW8GMsDPRInh9NNbqEPh
         DUEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f68.google.com (mail-wm1-f68.google.com. [209.85.128.68])
        by gmr-mx.google.com with ESMTPS id r16si141167edx.1.2020.12.04.03.54.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 03:54:32 -0800 (PST)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) client-ip=209.85.128.68;
Received: by mail-wm1-f68.google.com with SMTP id f190so6826434wme.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 03:54:32 -0800 (PST)
X-Received: by 2002:a7b:c087:: with SMTP id r7mr3791014wmh.153.1607082872591;
        Fri, 04 Dec 2020 03:54:32 -0800 (PST)
Received: from [10.9.0.26] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id u26sm3027316wmm.24.2020.12.04.03.54.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 03:54:31 -0800 (PST)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Kees Cook
 <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Masahiro Yamada
 <masahiroy@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
 Steven Rostedt <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Daniel Micay <danielmicay@gmail.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Matthew Wilcox <willy@infradead.org>, Pavel Machek <pavel@denx.de>,
 Valentin Schneider <valentin.schneider@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Kernel Hardening <kernel-hardening@lists.openwall.com>,
 LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
References: <20200929183513.380760-1-alex.popov@linux.com>
 <20200929183513.380760-3-alex.popov@linux.com>
 <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
 <1772bc7d-e87f-0f62-52a8-e9d9ac99f5e3@linux.com>
 <20201203124914.25e63b013e9c69c79d481831@linux-foundation.org>
From: Alexander Popov <alex.popov@linux.com>
Message-ID: <9b9861c0-4c94-a51f-bbac-bd5e9b77d9e0@linux.com>
Date: Fri, 4 Dec 2020 14:54:26 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.3.1
MIME-Version: 1.0
In-Reply-To: <20201203124914.25e63b013e9c69c79d481831@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as
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

On 03.12.2020 23:49, Andrew Morton wrote:
> On Thu, 3 Dec 2020 22:50:27 +0300 Alexander Popov <alex.popov@linux.com> wrote:
> 
>> On 30.09.2020 15:50, Alexander Potapenko wrote:
>>> On Tue, Sep 29, 2020 at 8:35 PM Alexander Popov <alex.popov@linux.com> wrote:
>>>>
>>>> Currently in CONFIG_SLAB init_on_free happens too late, and heap
>>>> objects go to the heap quarantine being dirty. Lets move memory
>>>> clearing before calling kasan_slab_free() to fix that.
>>>>
>>>> Signed-off-by: Alexander Popov <alex.popov@linux.com>
>>> Reviewed-by: Alexander Potapenko <glider@google.com>
>>
>> Hello!
>>
>> Can this particular patch be considered for the mainline kernel?
> 
> All patches are considered ;) And merged if they're reviewed, tested,
> judged useful, etc.
> 
> If you think this particular patch should be fast-tracked then please
> send it as a non-RFC, standalone patch.  Please also enhance the
> changelog so that it actually explains what goes wrong.  Presumably
> "objects go to the heap quarantine being dirty" causes some
> user-visible problem?  What is that problem?

Ok, thanks!
I'll improve the commit message and send the patch separately.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9b9861c0-4c94-a51f-bbac-bd5e9b77d9e0%40linux.com.
