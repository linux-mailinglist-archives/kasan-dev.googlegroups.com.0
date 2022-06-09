Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5P3RCKQMGQEIZVBPWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E7DCF54543C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:37:42 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id y6-20020a9d6346000000b0060c2a6ed978sf751444otk.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654799861; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOUEzLL1v3UcI3M0wqDQfBpRn6VOjDZ+sArCOhXX44vhoRB/iI6A4FuF6ONlPTkCSS
         1I27Zb/hmXx8uwJEskLoo8mL3ApYeY31mke0AbF6ZteSWKr7CXkGKhUBpRjd3liIlhLJ
         TFel56v8SCpD//TWr8luKrG9dJgIe+GmKhlxg1NrWiQu8cpaLEGvmyPH1/y5xtonTLZL
         SEvALTQy8Jnp6s+uIcdKewuPyaRzzYRh6uWC6KedbZKlgwEnkVzZNYfRzekOvHtj2zq/
         h02VvM3cBWuBBQhWH0+fmo32OI8flmp75SdvMBGpBbxTKpFWrq7Bq/majntKgnqg9hUu
         KOiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s/Bl7cTYHJ+Z5WI02Gh1SPKDSSKWS8ds6ZylYFJSM74=;
        b=ttMuUT2LYVo1ESwUqTud5Edq+M80AIYiXvXCjyI50ixj3i5gM2/E33bm4rBa8tgW+i
         8xEUEhizYKi+JF05yeleWl2yj7soUn952UyemUpWv5i96JskEUlBHDEBAShJJzmKz60m
         7P/orXdHdWXXlNjBC2rJ0h0u+Wjq0fmjV4U0PJGCdpkaq6MGDPBUY2Srn+hCkgbbQ8NL
         g38yylxfOmAAKLbGESG+Mn45iqkp1PhCPcVVWG33s0fdATjGW5uSG8n1XGl8j1kAUzoS
         hIlRva/aI2Xh5MNEUgwKGA9m30v+I5SP0UF+SQyNAKoz1bUsY9iows0rXKx+vYPwzuKO
         zOKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RXSLJN2r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s/Bl7cTYHJ+Z5WI02Gh1SPKDSSKWS8ds6ZylYFJSM74=;
        b=EA4KW2j+Jkn5s/MhpNmRzTnNpzVwq4kx1rl1c2ZuJBOnkVSr3w3SFRQ/fIr8jpJPU5
         6e4wQ7/FjeSeQO7ppyjvMAS4uRpVCl7DfIhu6bM3kWUf5WBVowFdthWbLbuwDd4LUxAv
         XaVV5A7R+uSiIVKraw7m7s7Q+DIws8nuFz7kNI3jkEz+c+k652iiumOG0UPwCMKNjGrp
         JznIpk7HpYhoNM4cwbhphMOKqpJzYs3shrtMmI74OQH4O/W/e6ccH6R3j3FwlCOR++K1
         FVuBniqjL+EGXFq3zGpDyON3bi3X8Q2119t2excIVzrt3Dx/FESgu3Xg6R5zI/CPl8Kq
         IeTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s/Bl7cTYHJ+Z5WI02Gh1SPKDSSKWS8ds6ZylYFJSM74=;
        b=Jb9zPLPnvScSihX83qvbIY/mbrZa57uYCDljDhI/uiCsokETCDYllKpReVUiMgAjzw
         CfCvyZtBRb/rONyUVcqHE0tzrwOAcPBhUAXXMxohfUclVi06U+GoMg7eNBma1vysTlH5
         o9l4CJCly6EuSUXVdevKcTjUd5jLlhMcr/0cw+UI3lESia6DTuZo7A7GT81DRLRakVPQ
         wZWReUR2JoLGChS+az2t6aQJN5OK2BtM1cYgj1S3sMoRWNZNaLUhR5I6LEWMUTpEmSS1
         SxzUSh5J2IaxPz27bOVRDfRRqnvaf7+eL57+85cvQTgqjB4qNj7Dg/0Ijww537QDV3Lt
         F0yw==
X-Gm-Message-State: AOAM530veQACHfN2PWMwFO0Kp/vs+Q/lNCljqpOMxcXk2JSwDsNgb1LL
	gZNqS5wRpNC+RfxvZHjjxqI=
X-Google-Smtp-Source: ABdhPJy/uwmve1nw952VfWWb9utrBrEo191pH16CBqTYQe7RqeTpNaY5SIhC4goLNpraihJqMZne/w==
X-Received: by 2002:a05:6820:1686:b0:40e:ae28:643 with SMTP id bc6-20020a056820168600b0040eae280643mr17167283oob.69.1654799861806;
        Thu, 09 Jun 2022 11:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2224:b0:32e:c693:1736 with SMTP id
 bd36-20020a056808222400b0032ec6931736ls2981907oib.7.gmail; Thu, 09 Jun 2022
 11:37:41 -0700 (PDT)
X-Received: by 2002:a05:6808:3089:b0:32e:f7fd:627d with SMTP id bl9-20020a056808308900b0032ef7fd627dmr967390oib.181.1654799861370;
        Thu, 09 Jun 2022 11:37:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654799861; cv=none;
        d=google.com; s=arc-20160816;
        b=vUQq5DXbW7FP+kRxcAtZxsvTu4oV+F9HM1njC/Bja2LomAC9VTH32F+KCAic009kho
         dkWBE1ZRGrVr3s/+GmKPx4O1dpqf4cheBCKXh3RWyfYyTQuX2xXuh3PisWGnRH6vvmao
         dBQFVcoeq/7+nWkZZDCretPBoe/rL79sKvNiwOuMCcEdd6EEtKncPOrgLvw5eLpuiUGE
         D2Q9r9RmQimb8KTuBJsurX5uzDZI50k46Ub1B8hhkMEwsaC+SjrJRdbAVjgj6FP8obKK
         nDp2XKM6bs4VCj89V+HQ4+NX4tJG14vDVgSHgspeCTx+VxhBQjtel/uWO3cfbtPJWFAw
         z4Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Hj76BK0VwQ76C6uNuhyu2UOiDef16x6n+WhyTwiuL8=;
        b=GJw8dPsioYe34CcQYXHu2/O9v0CN4WuiVnf7smGBTroGOA3DD86W4W4wWgZkFT/M+R
         g/V9Ykc3FDDc1rFkvV723YTwbNxUK8q0Na1kleAAiRT1vPGdhWsjygX6aUoJq8WIL4Rx
         E6w5UEF3mZM5IJwzSQLTNhZZNnwSzUj4cQBlSlchRw1yMErvIDifEZhR07mFqi08s1OQ
         qnLFM4OCf2aubuh2XOtH0ZfZHsRBwDZ8RSRR/yHXDnOkblYBxm9T8pGvcyerqFflbJzR
         HVvE3yF/FPTjLuGPwiy3bMLlnuQOk9g0GKDcgTSB4quqJ9Gu6xkuoSg7+HjL8N05Zpy/
         6law==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RXSLJN2r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id bq10-20020a05680823ca00b003222fdff9aesi1832806oib.0.2022.06.09.11.37.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:37:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-3137316bb69so55648197b3.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 11:37:41 -0700 (PDT)
X-Received: by 2002:a81:9b0c:0:b0:2f4:c522:7d3c with SMTP id
 s12-20020a819b0c000000b002f4c5227d3cmr44383963ywg.316.1654799860756; Thu, 09
 Jun 2022 11:37:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
 <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com> <CACT4Y+Zq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Zq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 20:37:04 +0200
Message-ID: <CANpmjNNC7ry59OXsJrPMf56Xi63chexaDfnP4t8_4MG7S5ZgCg@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RXSLJN2r;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 9 Jun 2022 at 18:53, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> .
> /On Thu, 9 Jun 2022 at 16:56, Marco Elver <elver@google.com> wrote:
> > > > On a machine with 256 CPUs, running the recently added perf breakpoint
> > > > benchmark results in:
> > > >
> > > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > > >  | # Running 'breakpoint/thread' benchmark:
> > > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > > >  |      Total time: 236.418 [sec]
> > > >  |
> > > >  |   123134.794271 usecs/op
> > > >  |  7880626.833333 usecs/op/cpu
> > > >
> > > > The benchmark tests inherited breakpoint perf events across many
> > > > threads.
> > > >
> > > > Looking at a perf profile, we can see that the majority of the time is
> > > > spent in various hw_breakpoint.c functions, which execute within the
> > > > 'nr_bp_mutex' critical sections which then results in contention on that
> > > > mutex as well:
> > > >
> > > >     37.27%  [kernel]       [k] osq_lock
> > > >     34.92%  [kernel]       [k] mutex_spin_on_owner
> > > >     12.15%  [kernel]       [k] toggle_bp_slot
> > > >     11.90%  [kernel]       [k] __reserve_bp_slot
> > > >
> > > > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > > > O(#tasks) due to storing all task breakpoints in the same list and
> > > > iterating through that list looking for a matching task. Clearly, this
> > > > does not scale to thousands of tasks.
> > > >
> > > > While one option would be to make task_struct a breakpoint list node,
> > > > this would only further bloat task_struct for infrequently used data.
> > >
> > > task_struct already has:
> > >
> > > #ifdef CONFIG_PERF_EVENTS
> > >   struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
> > >   struct mutex perf_event_mutex;
> > >   struct list_head perf_event_list;
> > > #endif
> > >
> > > Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
> > > And possibly perf_event_list instead of task_bps_ht? It will contain
> > > other perf_event types, so we will need to test type as well, but on
> > > the positive side, we don't need any management of the separate
> > > container.
> >
> > Hmm, yes, I looked at that but then decided against messing the
> > perf/core internals. The main issue I have with using perf_event_mutex
> > is that we might interfere with perf/core's locking rules as well as
> > interfere with other concurrent perf event additions. Using
> > perf_event_list is very likely a no-go because it requires reworking
> > perf/core as well.
> >
> > I can already hear Peter shouting, but maybe I'm wrong. :-)
>
> Let's wait for Peter to shout then :)
> A significant part of this change is having per-task data w/o having
> per-task data.
>
> The current perf-related data in task_struct is already multiple words
> and it's also not used in lots of production cases.
> Maybe we could have something like:
>
>   struct perf_task_data* lazily_allocated_perf_data;
>
> that's lazily allocated on first use instead of the current
> perf_event_ctxp/perf_event_mutex/perf_event_list.
> This way we could both reduce task_size when perf is not used and have
> more perf-related data (incl breakpoints) when it's used.

I don't mind either option, so keeping task_struct bloat in mind, we have:

  1. rhashtable option, no changes to task_struct.

  2. add the breakpoint mutex + list to task_struct.

  3. add something like hw_breakpoint_task_data* and allocate lazily.

  4. (your proposal) move all of perf data into a new struct (+add
hw_breakpoint things in there) that is lazily allocated.

I don't think perf is that infrequently used, and I can't estimate
performance impact, so I don't like #4 too much personally. My
preferred compromise would be #3, but at the same time I'd rather not
bloat task_struct even with 8 extra infrequently used bytes. Am I too
paranoid?

Preferences?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNC7ry59OXsJrPMf56Xi63chexaDfnP4t8_4MG7S5ZgCg%40mail.gmail.com.
