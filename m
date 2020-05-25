Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ4EWD3AKGQEBNHZH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 294191E1376
	for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 19:36:41 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 186sf17953830ybq.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 10:36:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590428200; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJc3rp/DDlG9c57U/d7fxA/0czXtC4w/fWuzZ/jqyRB6wzNzzAVO0r6zi5gL4wy0eG
         LFU5qM0VYN6owYWIJKK2mrpvxXP6mXoUNwv6jVzT3vAqIkkh+SDi6e0xEt+yDJQ2fR8J
         AZSStKOmStBflXAbolIOyYaaz/t02fQPbB9PtFGsKDi4175h73dqZMVslsUNr4FztH56
         VyniREqRH/z2y9NtxMQ3Z6XayqAhsMkRo62/nGgIkJUQfliJ0ozjZCJBRz2V+zo488yM
         ZHMr9FCE+/DEWBLMER6yu300zfMdBVPgvJFpwcnIrRF87d2N7qLF9BhkiXLlp5ppRI+/
         h4vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XC8QxfuzMp0rTQYqNWMMegRNigD9ibJg+uSl9YXD0Gs=;
        b=oca2l4EBkK9fthI+jICelNUAKBH+Z4ZP/twjKbaliXHrZ1EsEW10WOVG9mv4mc8tBo
         Wyqht1eNFGpdL7W0UM/Wo7EGvJAFI0dkRpFxObvSUk0juwRqTRiJX+mcwvGcPQ9hq69b
         o1fu/e8SOc7D3pYFT24R53iPL+KMw2afEcKaJKUm/RhQS9e9OCbdVxYagfc7MAOKp2cp
         XfgP1Ycenw19cbYCy0CRKzJC1t68Ab+s1kPuNAS/afzn1rvxbRZ2PxXUQIX8Sq2IaMqn
         9VEHQgDD06I58DcHQtYzNemDR1fCfICea9ApwAxVm7CM5s0rcoUV9Cme4cU45hpsc/qK
         0tcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vrKxB8Ua;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XC8QxfuzMp0rTQYqNWMMegRNigD9ibJg+uSl9YXD0Gs=;
        b=laPkMbgQTot1xCD/Gt8uqR/uLNSg4bnH+5S5lFo0pEBFwM9Vj/FljlQGtHNU4u6Tk/
         rrsiqcRhgpXSwSHWp7HNNLS7PwY/0emqbP5vAiZVfgjpIEg7Ojoq8DKgpLeMuCENwBpf
         tfIeFKNQunR1JVNv7XSKv1Zto8m9aECoH2eQOmd1zFqcs0ILfWGke9ouHc1DZ9qiPfPG
         KTOWTK0NMXvhW13AC6szh8rG8ba6+dxwu4lFH5yUj3UHAT/Qqe/pENl7e+J27q5ZYDCb
         ZzJUs/dscInn599iuesTMbglnOzFW3wVWp78R9+LnKIt7yUXt1jcHD7Sn2KkE1tuBxZg
         FVQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XC8QxfuzMp0rTQYqNWMMegRNigD9ibJg+uSl9YXD0Gs=;
        b=sCludVdjL3ciKaXNLR9zZM/C115cu1CpKWm9TnqIPJhPxmdstgR1rPg5oHjet6IUSs
         guANKaZhm3VIAtUgD0dPKMBuUSSy8onJQqpsiLsLJbM8JMNnlsb/Lo3lwo57nZP3+4UJ
         b35JYoNFhb3O+vKRB0QkwXy7FDcUltNdhBMxFzTuOZtgY0zSznLLQ4IqREQzstCOS9U1
         8bXZvECjApWzaVb+EsBXlT+V3N4pa9REQUBWdOeaK2SbdWti/yvFE6aH6D7kqGffLOnh
         Ezf5+7OmnwrM6PMs7pLyn1TQAEwbCEirwWkzvEyt2IcqGYYCEZfmJO/5F0F3ecrj6Li8
         FcSw==
X-Gm-Message-State: AOAM530czD1LSWdgHoaF7p4c39WAMagk+ZR3EuyI+WLVgBdktQ5QsIDC
	zNSvezWLJIYsB/7ZS8r5a8c=
X-Google-Smtp-Source: ABdhPJxmdQ9u72YGW2GGv3NGyD1DM7aM7Up+4ZqZfqOQKEQ1nq0/LszG8DVirYURGzIuGneHDcm6Cg==
X-Received: by 2002:a05:6902:6c3:: with SMTP id m3mr41051235ybt.70.1590428199960;
        Mon, 25 May 2020 10:36:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8684:: with SMTP id z4ls500659ybk.4.gmail; Mon, 25 May
 2020 10:36:39 -0700 (PDT)
X-Received: by 2002:a25:4f44:: with SMTP id d65mr47499090ybb.149.1590428199571;
        Mon, 25 May 2020 10:36:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590428199; cv=none;
        d=google.com; s=arc-20160816;
        b=nxbInwLTlpUsNxUjiC3dWS8l/aV0xTfDIU3xn5I2VpczMvxYDUk5+vUHWNq1Cs21us
         HuN+kJZRzs6/UvRZditoEaJjOn+EsX/RSAzI1hK5wI9iWR3Y3HNbwBIn6RkdwoBl4EDu
         /kObglX0iEmZ5NwMbOt7OrHERsuqZl6XTEv7ySwjExXrvjmxYbxaxH1WurUc6UduhyXq
         WQCC1hTuwvxFMyUB7UPjacV5WrahCmAhq81W3GKMDDkauTwBvmXHRH5KOOnDMJDrYlo9
         W/l+0faNBcFy5wtJW6/fn+56+lQ5pZ+NI0byvI6TWfakQRp4tsjLYhLoPp/KUnubkSrv
         F0Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IJjU5AD78PQmMgIoxlhUE3XdqOGH2pnJ5GvxPy/ZWeA=;
        b=Gt0WjZkgeoGgD6jQJBPPGJuXkV1esDS1010FRc6DjHvUHiNwfyhGcoa1Emd9kPoW92
         TcaG/CwEv0Oapl/UtvSJdG/Jt2a0K/GJcGOBj/SLFdHw7mx2UMkvfpOIXWqom3+zqCnp
         iO7jBSdNpt97iW6z0rMH2hzIEZ8KV9BzviyH6CilTJDB1+VbWhBgrlYsJRER8LbOsBKC
         RyEsyt5cm7pGW3ijHB64ThD4Fsycr2ayrdvy9mDP1/FQ3zgsW1m46PQXMkKyqiJM5tnt
         SmomfSc+AY5ZTr6+KLbj6682mOq/yoZyIH9BSJEf+wA2dtXZPIm3HBDRajttfVKcL9UC
         pTwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vrKxB8Ua;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id a83si1366684yba.1.2020.05.25.10.36.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 May 2020 10:36:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id a13so7693484pls.8
        for <kasan-dev@googlegroups.com>; Mon, 25 May 2020 10:36:39 -0700 (PDT)
X-Received: by 2002:a17:90b:1994:: with SMTP id mv20mr21281595pjb.41.1590428198538;
 Mon, 25 May 2020 10:36:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200522015757.22267-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200522015757.22267-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 May 2020 19:36:27 +0200
Message-ID: <CAAeHK+y9qz5P-WCWEGwUx__XVzPXTddcOXsFDnFvh_1-k4Opxw@mail.gmail.com>
Subject: Re: [PATCH v6 0/4] kasan: memorize and print call_rcu stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vrKxB8Ua;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, May 22, 2020 at 3:58 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This patchset improves KASAN reports by making them to have
> call_rcu() call stack information. It is useful for programmers
> to solve use-after-free or double-free memory issue.
>
> The KASAN report was as follows(cleaned up slightly):
>
> BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
>
> Freed by task 0:
>  kasan_save_stack+0x24/0x50
>  kasan_set_track+0x24/0x38
>  kasan_set_free_info+0x18/0x20
>  __kasan_slab_free+0x10c/0x170
>  kasan_slab_free+0x10/0x18
>  kfree+0x98/0x270
>  kasan_rcu_reclaim+0x1c/0x60
>
> Last call_rcu():
>  kasan_save_stack+0x24/0x50
>  kasan_record_aux_stack+0xbc/0xd0
>  call_rcu+0x8c/0x580
>  kasan_rcu_uaf+0xf4/0xf8
>
> Generic KASAN will record the last two call_rcu() call stacks and
> print up to 2 call_rcu() call stacks in KASAN report. it is only
> suitable for generic KASAN.
>
> This feature considers the size of struct kasan_alloc_meta and
> kasan_free_meta, we try to optimize the structure layout and size
> , let it get better memory consumption.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

for the series.

Thanks!

>
> Changes since v2:
> - remove new config option, default enable it in generic KASAN
> - test this feature in SLAB/SLUB, it is pass.
> - modify macro to be more clearly
> - modify documentation
>
> Changes since v3:
> - change recording from first/last to the last two call stacks
> - move free track into kasan free meta
> - init slab_free_meta on object slot creation
> - modify documentation
>
> Changes since v4:
> - change variable name to be more clearly
> - remove the redundant condition
> - remove init free meta-data and increasing object condition
>
> Changes since v5:
> - add a macro KASAN_KMALLOC_FREETRACK in order to check whether
>   print free stack
> - change printing message
> - remove descriptions in Kocong.kasan
>
> Changes since v6:
> - reuse print_stack() in print_track()
>
> Walter Wu (4):
> rcu/kasan: record and print call_rcu() call stack
> kasan: record and print the free track
> kasan: add tests for call_rcu stack recording
> kasan: update documentation for generic kasan
>
> Documentation/dev-tools/kasan.rst |  3 +++
> include/linux/kasan.h             |  2 ++
> kernel/rcu/tree.c                 |  2 ++
> lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
> mm/kasan/common.c                 | 26 ++++----------------------
> mm/kasan/generic.c                | 43 +++++++++++++++++++++++++++++++++++++++++++
> mm/kasan/generic_report.c         |  1 +
> mm/kasan/kasan.h                  | 23 +++++++++++++++++++++--
> mm/kasan/quarantine.c             |  1 +
> mm/kasan/report.c                 | 54 +++++++++++++++++++++++++++---------------------------
> mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> 11 files changed, 171 insertions(+), 51 deletions(-)
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522015757.22267-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By9qz5P-WCWEGwUx__XVzPXTddcOXsFDnFvh_1-k4Opxw%40mail.gmail.com.
