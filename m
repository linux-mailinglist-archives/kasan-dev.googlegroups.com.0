Return-Path: <kasan-dev+bncBCAP7WGUVIKBBHPS26XAMGQEJVSYMEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 28CA785D9C2
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 14:22:39 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-68f5184049fsf9039026d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 05:22:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708521758; cv=pass;
        d=google.com; s=arc-20160816;
        b=uixzt0sLI2BSExtM2wvCkTekF5wUOXeHg7nEtGPQ37jLio487ysc0DDSB9e/+VEMRk
         q2SGhx4NeVdRnBEEbJqilhFmGAaLQcWBv0mgH9kmB7KAZjhGwcJ3t/lz5RDFETdMA5C3
         zb61tSDtGpUBSnKHCwZUS7gtwa3aNIWFeQlb/++uQQEWoiTSoZ98DuUxt2p9y29pr0w7
         pRQircffOsuX5+eKU6miF5bjZCTG52Qoa6qfn2BMvL9uNVXBQ1d/KXrdNBr2M/tven/C
         cHIm+d2uyzDHEX0xfbvGr7Dm8RzoejFYp3ZMvAxMgg9S3rL2ie0h7j0PHvYqHlJlh71z
         xwNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tTjsw+q8FmTD3SrYcKfyDaiZKQyZKioykyqLQu7pny8=;
        fh=ClkW4lL1kPqnucjLeBLTdjbM7lhfTmxBBf1fEevMMvo=;
        b=ns/Rv/jpIQsiyrU3sdXqv+nZvQbxJGoRiZ+7cd4Vy6pDyz+T6MFx7un0WyCLD4kGNx
         Hnh4VPh6k9ILt09jf+B5Gwx+t1xzP1dcE3YBJzmHsLep2OueSW+wHQ9ejS782Pkw6DYw
         os9S78/lAzIpSaoqlscVwKC0JHjQN5e49AzIxARMEsfx9C82TY3e48sQc219MeEgJR+S
         eTsyIyadA2ZmBdM7koFRB/85fL1s50e9KVaV3VLcfKcit4zvzduHGa0Z7YE0770JWNIC
         71Z5y/wtgFH/HRnR5+QDpGxD1SkvS2PUgZChkOSPN/xrZijgxrCuZZKb14feKfQiQNl4
         3P6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708521758; x=1709126558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tTjsw+q8FmTD3SrYcKfyDaiZKQyZKioykyqLQu7pny8=;
        b=R4Zf/nps5Mcp8u0DEXCZoveP6QBetaNV+djnUPIPciYyt7zzWecAwMR96vIdZk1fcG
         8vxKydx2NYJoF1SW6ifW6f80ubaEFHSNXxVBVvHLqa1rUsJR5c2b3AH4/dTjrc5GLzMq
         Da3SaL3i0RXo7SCu4q4L1P/6p40rRSXi/Youi47qgt2HmRnp2JNCl0QgmrRYQMI595JY
         s9X7UIvbu47KLqd88fVITcUHTOmhYDLx6UvApgaKribdnZHs/upX1nnJGg528FO+uXjj
         DWnkEkwylcdWuth+nRqMKegdUgLhCJL7EO7LIe7HPbW40WKfFvSK7kMvUmTmSccLUPkT
         Oung==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708521758; x=1709126558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tTjsw+q8FmTD3SrYcKfyDaiZKQyZKioykyqLQu7pny8=;
        b=CQkegfLnXXmvnLZBsqKeYrvSZMBOI/xY/9QeMTa7/wnBILjQV2E8YscyP7OXOssjjD
         0hNC1kpXjpwSbUIyWIG5l6fuCpZMW0U+QrMoexh5KLui8jgJDbL5vmypYoiKc8zQiTD4
         Kb2niYzyWAJwM/98hYbykLO4U7ilptCjHhBFI8Nto0LBuD3Q/vY0maIdOy/CpuXb8SPw
         mjtHPRge1aNThWbv9YzrDAv3BgMTHzQIYTXK4a5d4yV7FC+7awfbv2xT9kGtEmwe0BVc
         VDteGsDNZvFCQTlJh2PFwOighF++YhiRyMyuQpE0rmm2FfTTlI5mw8BdCYmLldrJ9Wdi
         ILnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlieqDncWINMOzhuLTCtlIOcJfUCKfDaaBZqCW1p5yhNme16wvrT7CRsdDLQ6412Y7UbswZ1iWZN5dA5xyAv3sUx1N8k9Ulw==
X-Gm-Message-State: AOJu0YwMVyzc+GkGIJ/iffBOvCSJ0vo/JGoWtI4r3qaj9RvalZD90Do3
	kksaM6ijYEvEschYhaemDRUc72+69icdkCAM2cLv365K9c3MvC60
X-Google-Smtp-Source: AGHT+IFpKAi2icdzCeFjZK7U9ckC1uu9imrJH9T8fcIgfzlAskIzrfttU0iBsjL14062SQn+ph4EAQ==
X-Received: by 2002:a05:6214:27c8:b0:68f:8921:6924 with SMTP id ge8-20020a05621427c800b0068f89216924mr9265832qvb.12.1708521757985;
        Wed, 21 Feb 2024 05:22:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:242b:b0:68c:c65a:40a4 with SMTP id
 gy11-20020a056214242b00b0068cc65a40a4ls154213qvb.1.-pod-prod-05-us; Wed, 21
 Feb 2024 05:22:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWdOAa1spMUJ+oFT1TiXq7rTQpuT/dG+CqTYZDbteQgGJVGvc/HFoq41Fy6d0fmn4kaMvZUm0xZpqZ2KH1PqIc66isZyVwQ3r3EQ==
X-Received: by 2002:a67:f8c7:0:b0:470:7a7c:2d1c with SMTP id c7-20020a67f8c7000000b004707a7c2d1cmr3168546vsp.8.1708521755468;
        Wed, 21 Feb 2024 05:22:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708521755; cv=none;
        d=google.com; s=arc-20160816;
        b=d7lxC3tmv0l5sw8KO45hluaX1cXNQOqtjqW7aZKncvm7dbGxb8sDBwSiQ6j14BUNIc
         zyBut3baIJSM251I7+t8R5hi4R1+bbYEE3zceKizXZnh2Xl+qc4xt9xzw4pnTrdUw4mO
         XUJAcvGwxpdpp/VcYpnoVNx4N10LbU0FB1Hq7+zfKfW/wIUj/1Q2Cc7pyuFSsNuNQKbu
         4pCk7+xzSQfGS8tkg2CEJNvCqY8VglMTMf2dm8EEF0TGvNexmmFDH50AaAxn5f9HYLby
         SzKEekmZPyXCDdGzixV2seXI4PJ9GB1C/hAvtCBmwsW/ll0GcwVV1jIhW9xfHcwSSSBX
         1K1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=KrK7iNq4+GifJCxvrxb6wK+cw9XXTFp9UkvXE9nlj2Y=;
        fh=cdH+B5M6Pb3+gu+oHdhaKvkn6DouunD6Cx/FeETx2Bo=;
        b=qPYUuO7tqMbHu1lCwot1R0M1lJUNxGHOzw7aA7HVSSihf/pnv7jykNu8s629lgttUh
         WpbgZU8d/hcafSYEGLiWJRgCVZS9pR+sUI1X2ksP19p+6Ndq9kdlr4mn44k1lsbj5RXz
         Lr0bQ2ldIrXcpxkelFHwkrnaFNXYaI/dYopc7/gixoZviRAjU0BsEvYhaoBJqQ+dvfSI
         t8fSE8BJSdg6T5PS0a6rsLoG6UKRSL0UR4+/m93lfrjHnZ8xikXGZHObRtw5N/FS8nfC
         61odnwibHICxz9/dQDE98Gczh2KDC/h/rs/Hs8HgUjzTS799zMBarwjwA2PEllAioYkp
         a6TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id eo5-20020a05622a544500b0042de5737be3si851177qtb.4.2024.02.21.05.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 05:22:35 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav118.sakura.ne.jp (fsav118.sakura.ne.jp [27.133.134.245])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41LDLFIf072277;
	Wed, 21 Feb 2024 22:21:15 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav118.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp);
 Wed, 21 Feb 2024 22:21:15 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41LDL68M072234
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 21 Feb 2024 22:21:14 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <c5bd4224-8c97-4854-a0d6-253fcd8bd92b@I-love.SAKURA.ne.jp>
Date: Wed, 21 Feb 2024 22:21:04 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>,
        Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>,
        akpm@linux-foundation.org, hannes@cmpxchg.org,
        roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
        willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
        void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
        catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
        tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
        x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
        mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
        dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
        rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
        yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
        hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
        ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
        ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
        dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
        vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
        iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
        elver@google.com, dvyukov@google.com, shakeelb@google.com,
        songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
        minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
        linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        iommu@lists.linux.dev, linux-arch@vger.kernel.org,
        linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
        linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
        cgroups@vger.kernel.org
References: <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
 <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/02/21 3:27, Vlastimil Babka wrote:
> I'm sure more such scenarios exist, Cc: Tetsuo who I recall was an expert on
> this topic.

"[PATCH v3 10/35] lib: code tagging framework" says that codetag_lock_module_list()
calls down_read() (i.e. sleeping operation), and
"[PATCH v3 31/35] lib: add memory allocations report in show_mem()" says that
__show_mem() calls alloc_tags_show_mem_report() after kmalloc(GFP_ATOMIC) (i.e.
non-sleeping operation) but alloc_tags_show_mem_report() calls down_read() via
codetag_lock_module_list() !?

If __show_mem() might be called from atomic context (e.g. kmalloc(GFP_ATOMIC)),
this will be a sleep in atomic bug.
If __show_mem() might be called while semaphore is held for write,
this will be a read-lock after write-lock deadlock bug.

Not the matter of whether to allocate buffer statically or dynamically.
Please don't hold a lock when trying to report memory usage.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c5bd4224-8c97-4854-a0d6-253fcd8bd92b%40I-love.SAKURA.ne.jp.
