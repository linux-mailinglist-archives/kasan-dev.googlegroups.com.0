Return-Path: <kasan-dev+bncBDQ27FVWWUFRBV4DUTXQKGQEGGUUJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CF604114139
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 14:10:48 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id e124sf2334150ywc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 05:10:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575551447; cv=pass;
        d=google.com; s=arc-20160816;
        b=w9piWjjuyrFEETl9CFOzTzlHgTj8/zYTkBYwiyv+x1FIFgJj2iLsMpcmYh2ZiqSlll
         M2Xg2Wrql4/zVgQqMO5YkEcmxpWBO1BZGKVRfWxYmebly7vy8A7+O5z1KI4pX+Rk0PZ1
         OSELxgZT7QL/WKibfROxFzoa8ut4IlA4UcF1YaM1W4tMbX6do4J1pezRdNpAeBVHoqW5
         R2Wh7a9XzQ+dDG3g3F6/p8tPGDzSLeuetwJex6sGPq1OIyKRnAFNSz+c6vmhrpJ/YfnE
         VfnmSvKWpI6kp2s9eciN2Io+cBqUQmv9mOqeKb8WMLwHBI0C17noOZRn+/F/krwQGQgx
         y40w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=FmRhM0ZOc5EOVSJGSGifpdANYXKRWPQ12/l+x5zaqgo=;
        b=MagROUunbYwM+9yfw/lpaf88b//pEJdCvfk/trDd/1GINwqMspniSXho8dFLTgsa38
         geBzPRotcSo0f+8ihOWZ848LwlgX1XPqTlVX8WdNNZV+MMYaiJLFxy4g9wHySTTFsm5v
         dfbMn0SnzoM1PqHHc0TLVtubEavQmEjRZiFI/GGWuhPhg1K0U/UedL7D7xMalsiWD1xU
         aKqx4k2k40sM5kGz6RE5QT4kivarfTtsSt5/LUdG/3XKolHq9gi1uqbprJNysNma3dSH
         KFsauHFu0DcdlSSzpwhAWI6SQoyQ7LVLQAjxV7H+HiE/fzgijOsj33wUN3Jl56SIrhRR
         1Hng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="c/vG+WSN";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FmRhM0ZOc5EOVSJGSGifpdANYXKRWPQ12/l+x5zaqgo=;
        b=V8HjDUT8YGnrqLz46b3Quxc2EpLbqk55Cd56N/6lu1za9U/o7XMQaPqek30z8SiQKd
         Vo2J770Xg3pkC7ySobwdHARz728XZG+3gr5kNQAfH5iMdTDxX3DFc5ULNhEXK1LE9YrD
         JiCSub0mp9jwVGyTClr4BtUxjEB0tXbi6sjCsCXI7dF97U12BApR8tZIxMteBHn33T4A
         +6Ay0Exw+BTCzq3TWO7pcqeirELju9oqgJc1bH3URGL0ck0j5G3/Vo1xTgYOj9r8FPuO
         jIzYxU2zLznXgVcbj3NuQBU9OxRxRkOpWjLMavcyGiBJstbzlSyG5YuSFwhRlskVHLyr
         MGJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FmRhM0ZOc5EOVSJGSGifpdANYXKRWPQ12/l+x5zaqgo=;
        b=l17DSJDZqfKxZ4McivyqF6bgV8k22/oeDVrvqBXg3yqHNip/EZTVo1f/cfJePgDB2I
         4VLAi9R8PrVSpoQuZwvxZ194MoNqwQcPrKBe0JSpOAOZ0FVaWJqoAmmb3pGoq01rQ7Em
         6XRlzViRn4W4CN/K6odC7b1r79jj9gatUYmGZ87OPqizFB4AXaGLA6HD+T24xm5vTIGd
         e6hYNI+G+JzTxJumLi8GWsopLYwlSkGFH24213S1snDGs7Gpi8OOG9lcf3mytEH0U9lx
         2/2QILQKwS4zcHh4SkUxaOk/T4SXWWD2Q3PSsl8UQTlZbQN94hfMILLdjrkw1D56Vb+F
         7fGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUgmu6rlyHh+zrwL00bC2E1RQR5d88mypSWHVOb/eDxT4ruk7LZ
	gyh+Usvcs12rKwfo4Prl/SI=
X-Google-Smtp-Source: APXvYqxj7ZuDMAZAi28cMcGmQLjWnZKwP8QEAOJLltz+PJq1thg+ZCC9tExr6/TLFzEnCmNoLI4cyg==
X-Received: by 2002:a81:98c6:: with SMTP id p189mr5754805ywg.443.1575551447763;
        Thu, 05 Dec 2019 05:10:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:c385:: with SMTP id f127ls378042ywd.9.gmail; Thu, 05 Dec
 2019 05:10:47 -0800 (PST)
X-Received: by 2002:a0d:e614:: with SMTP id p20mr6193818ywe.5.1575551447317;
        Thu, 05 Dec 2019 05:10:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575551447; cv=none;
        d=google.com; s=arc-20160816;
        b=bQDAGY4qXZyLqDV2dGPPmUOxvjNKkl2WE4ihDNYLmPS684h2m2OZns8DqBorbm/jyL
         899P2fiby9gON5x8c21uQMX6kNTwO9nmEnXHtqx1A8oDBKd7VYThNj7ezxnV8GoPsKSq
         WbCZSOzBgQoGJVCG/INBAZBDOkE3I6aagz4Y8NEhnanE4rXH5SZjNKnFOPHISvuDN9oR
         mgRlhSZMYJDbN5LqLplom8HxFrIeBhXGHIIBhdTccS0gdRTz5kBbK+PFPjSebU5Xu2qx
         mq71WK8YJX1TOpMnyXfR5GkSCwojRDtyt8D+oCvtwYNdnu3b9xs+zJMo3ANEvwcJs+pk
         AqNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=1shdlwho7hLS2xdM5LPSjSImPuutbJXwb9rmf439njs=;
        b=fj7coAb4+RM3h5C2EUFt9sRxoE8CMRYSPGS7GburkkRldSUbB8CWUb6g8ZIjO/EAJh
         5B3wnoRHiw2ds6rSons6jHgA+FX3VLmT8pEey6nBrOz10OmTO22ct2HPGoCRkNp3vOkO
         IsTTX2GdtDClwoRP4eU8G2Vz73Y1h6rGIZO2mIbtj9jY/YXL7ctF2NXdOrLFc2OY7yUx
         ytsiuTPRegYZc75ISTgfIkLubnSIL1ew2PAlrUV4vayrbC3P32n1WmZ+11ymizq6EESx
         IDx50Fmt2IHUB2DiqzLF5KTIGLcabJQ5HPlCHEtA5Algb+Cg611E30wqVrdeoLPj2WxK
         vj3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="c/vG+WSN";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id a7si617471ybo.0.2019.12.05.05.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 05:10:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id o9so1244356plk.6
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 05:10:47 -0800 (PST)
X-Received: by 2002:a17:90a:7784:: with SMTP id v4mr9361713pjk.74.1575551446465;
        Thu, 05 Dec 2019 05:10:46 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id z64sm12695976pfz.23.2019.12.05.05.10.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2019 05:10:45 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Daniel Borkmann <daniel@iogearbox.net>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzbot <syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Andrii Nakryiko <andriin@fb.com>, Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>, Martin KaFai Lau <kafai@fb.com>, LKML <linux-kernel@vger.kernel.org>, netdev <netdev@vger.kernel.org>, Song Liu <songliubraving@fb.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Yonghong Song <yhs@fb.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: BUG: unable to handle kernel paging request in pcpu_alloc
In-Reply-To: <20191205125900.GB29780@localhost.localdomain>
References: <000000000000314c120598dc69bd@google.com> <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com> <877e3be6eu.fsf@dja-thinkpad.axtens.net> <20191205125900.GB29780@localhost.localdomain>
Date: Fri, 06 Dec 2019 00:10:41 +1100
Message-ID: <871rtiex4e.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="c/vG+WSN";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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

Daniel Borkmann <daniel@iogearbox.net> writes:

> On Thu, Dec 05, 2019 at 03:35:21PM +1100, Daniel Axtens wrote:
>> >> HEAD commit:    1ab75b2e Add linux-next specific files for 20191203
>> >> git tree:       linux-next
>> >> console output: https://syzkaller.appspot.com/x/log.txt?x=10edf2eae00000
>> >> kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
>> >> dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
>> >> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>> >> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
>> >> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000
>> >>
>> >> IMPORTANT: if you fix the bug, please add the following tag to the commit:
>> >> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
>> >
>> > +Daniel, is it the same as:
>> > https://syzkaller.appspot.com/bug?id=f6450554481c55c131cc23d581fbd8ea42e63e18
>> > If so, is it possible to make KASAN detect this consistently with the
>> > same crash type so that syzbot does not report duplicates?
>> 
>> It looks like both of these occur immediately after failure injection. I
>> think my assumption that I could ignore the chance of failures in the
>> per-cpu allocation path will have to be revisited. That's annoying.
>> 
>> I'll try to spin something today but Andrey feel free to pip me at the
>> post again :)
>> 
>> I'm not 100% confident to call them dups just yet, but I'm about 80%
>> confident that they are.
>
> Ok. Double checked BPF side yesterday night, but looks sane to me and the
> fault also hints into pcpu_alloc() rather than BPF code. Daniel, from your
> above reply, I read that you are aware of how the bisected commit would
> have caused the fault?

Yes, this one is on me - I did not take into account the brutal
efficiency of the fault injector when implementing my KASAN support for
vmalloc areas. I have a fix, I'm just doing final tests now.

Regards,
Daniel

>
> Thanks,
> Daniel
>
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205125900.GB29780%40localhost.localdomain.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rtiex4e.fsf%40dja-thinkpad.axtens.net.
