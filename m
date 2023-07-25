Return-Path: <kasan-dev+bncBCAP7WGUVIKBBSUF76SQMGQECGIQ5KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id EFFCE761886
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 14:40:44 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1b9e8e096f6sf815955ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 05:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690288843; cv=pass;
        d=google.com; s=arc-20160816;
        b=JkDqSSrTovU7xhD6derJKD9DfNahRbbQb2BdAFO4QzRcHwuEej8YG0A6rdWVFrg0pO
         /e/NyXXyf4Ok/CtnyXmg0jJCQlmdNx4oc+2gZHgBou8ViKyZ9VyfwpVksvGhfwwr4Y1R
         FeRKfv9yBZb9ZnPxQsP4vNgQUQlBPueChogjGEqHu3nGFtHZY6G1na6s8Wau2MWE0QcO
         Yvpam7pQ3dcTIQTVrUh1Tl+yMA8rHOpcADZpK0djkMmo98Q5YHKWBqOgXqEjk78oH+Bu
         0GCiL0VqGb8Iy1FlLA1/TExp9BDjJutqAT5rer6MGlyl0HB83pEg9Q9ImTjFdjXgb1qh
         S17w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=36N1RLV9Y7FEhgpp4BAeNlLyyx+OSIUJGlVBr2emzaQ=;
        fh=VwKJHJVMlQYnbAL2hmO8nT7Ie4y5JFSAD6akrrtD9H4=;
        b=hQzzJ6ZEG7iYUvVy3NpHgCxqtBI0Z8a23QP7ztY9K4RTgyk1hwmidkaDzksHiBBqpc
         TtabcV64QsMbAeN+RFRMypgoNMB4Ao9PUGp1YQucyk7QeEYUVd6DUZx64ZxNG/AXc2Ay
         GG3Ad2wFTvI+4pyv/wfc3VUcvUPTZ4/jVGwFzcS3nXtn2JO2hMpTDF7mUH+PqjUkzGxF
         xyTIzrSifCN9ANGwpZ9EJXhi+6gR2RJ81tKPubRaUPN8D4AcZN97faIZxbD/p0HecwYX
         yNcd/tDwbhG2ijaNcTb/SM5A0/re3C90IgVlrXg7ft7XkwVRwLdk3ORZVz+t/RDUaaj7
         g4gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690288843; x=1690893643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=36N1RLV9Y7FEhgpp4BAeNlLyyx+OSIUJGlVBr2emzaQ=;
        b=D2hV3+hw0gNfr45ydyGOYDjH2I1YUw9lUoZH4sFW+PWRhT436gmNKHGjpcEzxs+b79
         r3TkD6HtyACvJr31+RsEMrOW82lsHJX3fTj7IzlmHKnh7RV4nCXrICqdQzcLIR7SaNN2
         7olBYDo+w/JdignDsMz2arAxKmnOfEmz1wIF+GboG62mCgrzp3U9G0snmhfiab2heyny
         74fneY9n/6YC/8HXqO/Lt2JL+qVvXlmrn2i4yQqtO+c1R0enyN4pkmWJEuRuVliUWPOt
         ssgdQqIBjuwC79Wv2L0uahJKi0DZMNWc8y6FFnfwWENHsMZAuO4cgdPqyuqgTYB8NZpv
         6z8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690288843; x=1690893643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=36N1RLV9Y7FEhgpp4BAeNlLyyx+OSIUJGlVBr2emzaQ=;
        b=VuChdUwfW8KWLmiH+1iKrv5kh4UJs/g70tCxUFJqDGO5OK48J7ELrO3gmpdaJCVK6R
         qx8hH63lrxv/Af8EqWabbzdN/XjJgSSi7EX0rRAtCJavcFtsZqRHZlpR4W77khlvJ7aD
         fuQ9w2/9ootr4QvwIRgFgRjwOmyjDxpXIDdCph+zrDV9XaZa2xIMvAt4DFu2k/wG87+9
         x1s2r8mMghFtVSRXYU+8dNq52uwxxMkG7APHdn7rK+ZwK2/PoMN4Vxt0U1nYq1mDna11
         6fPakzpcQUuMBcKXDzxfrUgH1wo6fOIMoDiGcGfxOxMRyY50XEvrRNvoBW0ZGT0FBtI/
         e2mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLb38oyAhLxc5FnLEdVeacr2U9EhFxCbK+Zlp0/950rEW5oroBmW
	f/zpCuRo04YDcIh28RhlhMc=
X-Google-Smtp-Source: APBJJlE0xL77JaNmnvRQLlnoQqYTrFWJNq0LoFbjfbl+5z6jlx3z7KVCMNjLKLNP8oJoYq9l0uhbcg==
X-Received: by 2002:a17:902:e80e:b0:1b9:e99e:fe with SMTP id u14-20020a170902e80e00b001b9e99e00femr118962plg.18.1690288843260;
        Tue, 25 Jul 2023 05:40:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7014:b0:1aa:1b25:f18d with SMTP id
 u20-20020a056870701400b001aa1b25f18dls254452oae.0.-pod-prod-08-us; Tue, 25
 Jul 2023 05:40:42 -0700 (PDT)
X-Received: by 2002:a05:6871:723:b0:1b7:2dfe:c205 with SMTP id f35-20020a056871072300b001b72dfec205mr13798906oap.20.1690288842190;
        Tue, 25 Jul 2023 05:40:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690288842; cv=none;
        d=google.com; s=arc-20160816;
        b=N51a9PMl8/2SG5w0aWvoKJCeiUHmmq+oP6NmVVPZr9gNqLD9Z6STJMCcW6FZPL4kad
         4GJqvpl+SeWK0euCZCrQ0tAUrvsYBYimOWmSm3L+abhsoZ9aoa8Ac1bEI8YGXjfZr+Lu
         tIB9L+Hu4FnAiaFZnhbBYGEJE8pyhoMd9hHkPO3fTkqTc6t6JVaakurbDZWkcvwIyuzg
         ymlmwS+V9b/PxhNHnj/HrkAfihnKGdTZV2rKUxnYfj7xZbBPlUtLMvRK41wt68A8ftJt
         kAPwz77100T7uQjv4LD8lQXDGa3RIBE8LLApFPNV7qqN9nCu7pilZrtFoF0RqbihnwJH
         t+IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=DPBwsea4FuEfXyTW+jC3iwo0K/IJqmIC3PQ+DoV4zks=;
        fh=VwKJHJVMlQYnbAL2hmO8nT7Ie4y5JFSAD6akrrtD9H4=;
        b=hogTfCS32n5vUUx3giQ+O+tiepv5Wi2JzLUBBKwLNO4XwYez6Srkvns4V0vIT5oKsT
         8BbuJDFh1MikSYd92eLbAWDWqUn6ICUaXMZRozvSCZFRnmHjnNoBzKUAktvf1G4tykGG
         8Sf7RdmqpYea04/lNz37Gne3FbHUmCZ19GZSO3wk9YRjDoB/L/Xy0SAIFq6st17jxZZ5
         3ygTBTbxHjaJ7GxnuVGku4xF61/GXOfArhR4GlAF0F9to9bYlQ1wpFcte6RNC3ZKNo6I
         ZCRzbs/RH5m1wapeu76MUdEZ4ZjP39RAOxKNluaFlirFq5EfnlSivaitMKwRk7uxQMmS
         FcMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id bp13-20020a05620a458d00b00763d5f6718esi597135qkb.5.2023.07.25.05.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jul 2023 05:40:41 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav119.sakura.ne.jp (fsav119.sakura.ne.jp [27.133.134.246])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 36PCeGQT060305;
	Tue, 25 Jul 2023 21:40:16 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav119.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav119.sakura.ne.jp);
 Tue, 25 Jul 2023 21:40:16 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav119.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 36PCeFMV060302
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Tue, 25 Jul 2023 21:40:16 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <41b72295-8eb2-8609-7494-cb8f57c4443a@I-love.SAKURA.ne.jp>
Date: Tue, 25 Jul 2023 21:40:17 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH] Revert "fbcon: Use kzalloc() in fbcon_prepare_logo()"
Content-Language: en-US
To: Geert Uytterhoeven <geert+renesas@glider.be>
Cc: Kees Cook <keescook@chromium.org>,
        Alexander Potapenko
 <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>, linux-fbdev@vger.kernel.org,
        dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
        Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>
References: <98b79fbdde69a4a203096eb9c8801045c5a055fb.1690218016.git.geert+renesas@glider.be>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <98b79fbdde69a4a203096eb9c8801045c5a055fb.1690218016.git.geert+renesas@glider.be>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/07/25 2:03, Geert Uytterhoeven wrote:
> The syzbot report turned out to be a false possitive, caused by a KMSAN
> problem.  Indeed, after allocating the buffer, it is fully initialized
> using scr_memsetw().  Hence there is no point in allocating zeroed
> memory, while this does incur some overhead.

I suggest using below description, for this problem was reported by me
using a kernel built with syzbot's config file (i.e. syzbot is irrelevant).

Commit a6a00d7e8ffd ("fbcon: Use kzalloc() in fbcon_prepare_logo()") is
redundant, for the root cause that resulted in a false positive was fixed
by commit 27f644dc5a77 ("x86: kmsan: use C versions of memset16/memset32/
memset64").

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41b72295-8eb2-8609-7494-cb8f57c4443a%40I-love.SAKURA.ne.jp.
