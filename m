Return-Path: <kasan-dev+bncBCU73AEHRQBBBG6QYSMAMGQETJLTBCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 176E25AA199
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 23:46:05 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 36-20020a17090a0fa700b001fd64c962afsf141395pjz.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 14:46:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662068763; cv=pass;
        d=google.com; s=arc-20160816;
        b=koQL23sRtzZ5JrYjlaEQm28pfgZjxla7Cq3Epl/emuLqJ2ES1AJkjdpH0y33SOXJY0
         E25/Qd7DSk9W8wnGAzHITfsrNTqJjJxK87mS9o+VHPzC16u5UsUgpH32QCi5TQRc6d9v
         AwBzm4hszI1hrerxyX97cHGAFKejAKi+NNDs0/Y2xrNQqp7xRvFDspMDXIzSDfWEt4Ge
         Mn9jcHWdyq17DuQG0Tdo8t1E4hEAmh4Uod83UnkPpKFHQDL1s1SSer74ad6TV7cfr5ZA
         INEYJCcAoSfH2fLRYjTW8ymj0358ISD92CDS020cCwo+H3RQVFLvwS7XuwIXI3yp6jgE
         Np8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UoLIcDWhNI/tOdWJfcfm52+cHMcjzADeiLI+B1IRsMs=;
        b=oLVpWwAURZ0agxWBFtzHIeFYZh/JOp3Dyqs0SbhLrVnRf2iE1cdck70ui4JF2vYZuo
         YjYQjiygRXJHyzD7DWI4UVD7zbBWK9vcghD/O89hRvpAi/W07lC+Hsh44dKRu3snwAVD
         iYHKCnWSZqJhQekl0haPlcTxpz/bPqEZiSpU4C83sw6vUJNvuhfCEQ94ZvlNfqPkRxSl
         hIIPwOEIZAmJ9I0HDDDPHVjtsMSYi5GJk8x5U2Tqf/PU+/ECwEais7lLQhARuvqcb/90
         mMe+pV//o2N57anLLcfRZpf2nt/tngsHqJUZk5z/Jp/EfY9J6vHHZBOh1rpyzTDm3ZGi
         Qm9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=UoLIcDWhNI/tOdWJfcfm52+cHMcjzADeiLI+B1IRsMs=;
        b=Ezoim+u1J8dh+Wh9V5sa2M47g2hbqTdZaGlN+lLk+yBSWQOE8ci9S12INIcGIY84T7
         gieWQ+uwJgKI5ZUhxVthijoZD81IDAzehk5XyHRnX1wS4HRzf2n3NpihKgYWiOhCb9Ew
         YkMxnl4XIVhho8ltge9/MM8W/ShIO8xvcbi5IiYJD5MEMnWfOMLrBOd2YNgWmmeQW3eL
         Lb/8/ggFIrwrpgBNH8GPRKYL5sovWeshnyb4Y+SHZXWIKXIJvbhRbRz3d1BsfX2Cc5Ym
         Q7k4Fe3krR5BJiJ1BLR6sD45beOoXVGt/+tgA+GzVCaIDm748DpFfYaCBvtoplZyQdvC
         juCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=UoLIcDWhNI/tOdWJfcfm52+cHMcjzADeiLI+B1IRsMs=;
        b=i/RyhXB4zm8wNolg50arB9KB7XWWDghoTJGtpVqxEK+WaGHe8AOaobq5MEW2IF+F43
         4qyGhSs1IT6xRiz3+gbIhuvQMGiyL/EOzc46Dx3t8KJoF6HwJMxXGcCJK/QBPYWR7ZQa
         2OiqDyTyMJMpTzOWUxyrBZubNCh3kCZD5409R4Y/QP6KARSKHfiJD13wUSbIjW29k0TH
         Gi4cX0jauVCBD6DXHBURcctAyLMjqgMH4nqBqpgBhz4SP8W/6Y4FRS82kDDiykFVq0Gj
         H81DMTZerfaw2ZZswbaIZwgJiaO/uQIicjvzmUueWf15690Dug/IgPHefxwAgAxNRlr1
         hmTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1u/W/hVsCQ/v5tbfiLTy84wEonIcAn2FmO5h0KdPtvg4+Z4Zqs
	8FWorySKpAxHcUPbLu4y20Y=
X-Google-Smtp-Source: AA6agR66ktJ6InaSJcYs3PHg0DCUpt46jzzyMSWtVIbpv4P3b0CtCZmVLfz8AHdY3nz4RQvtQe5JQg==
X-Received: by 2002:a63:c7:0:b0:42e:8690:960e with SMTP id 190-20020a6300c7000000b0042e8690960emr12648383pga.234.1662068763476;
        Thu, 01 Sep 2022 14:46:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c8e:0:b0:538:2c07:9c98 with SMTP id c136-20020a621c8e000000b005382c079c98ls1654251pfc.6.-pod-prod-gmail;
 Thu, 01 Sep 2022 14:46:02 -0700 (PDT)
X-Received: by 2002:a65:6055:0:b0:42a:7b2b:dc71 with SMTP id a21-20020a656055000000b0042a7b2bdc71mr27614032pgp.23.1662068762678;
        Thu, 01 Sep 2022 14:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662068762; cv=none;
        d=google.com; s=arc-20160816;
        b=nIYcY+14Nxom4yGuJDiBQfRAr930p7FE1VyysXmakPD7lhM9xgPnxQKWf0s9dy8PKf
         huN+Qeo9EM85QzrUy5uF8+2ubVxWX6EAZcZGG29RCTGbZDjX0EirXuLx6hdG/97Mqt+8
         ahtusVct3YyFq3VUlxeqyN9Q3QNW/j1yW+extNIm20cUC19OOOM0mqxjrOpMicb60B3B
         fTAdZfVKNIp/3jAzLtb1aDJ+nzan6U0nujqkQCb4lrPXfp/LQf4SxLfx5ymTnOWEwK38
         6A4Hng++EixBEABSr4WS9yt5G7z3VGz9uVhmUiTXfQ7O3Vb4pOBFihYEFhqO8UCUc0Hk
         irHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=eZ9JQStRN5RkSNpQf7SHWxI3gQalXytUTalM0atr0c4=;
        b=m8kr6j9xozinWcZ2KS+o3Z/qbpCZsdXC7YwA/mIYPrVxAPjEgd0fzSC16FJxCT36D6
         aMrAqn/eeBhEO+vSfQqjNMDb+BkVlriVs2V/JgY3P00mGIwItD9z/L4KJs4nVXp8YGLn
         z9yBpZuH1/1pVpA2dw0qych1wB5EBfsljDncnnJ9P/9hyIcMEzdt55ZFQDr2tQgG59h2
         DUy+FmokNHVUraaPDQtL/RcniOyOhUmMLYfb4cs4rSH+f6CTDaBAQsLOn/fF4yGFOeRf
         wOBq+OmOwe+Zkk/w3GUxDa03Hz9rgPsoLfTxx/qVS/XfGuJ+fT1nMSmXAFJlnOHxPbsD
         350g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l13-20020a633e0d000000b0042b329f2ff5si2287pga.0.2022.09.01.14.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 14:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 06F9161F70;
	Thu,  1 Sep 2022 21:46:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 58693C433C1;
	Thu,  1 Sep 2022 21:45:56 +0000 (UTC)
Date: Thu, 1 Sep 2022 17:46:27 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901174627.27c7e23d@gandalf.local.home>
In-Reply-To: <20220901173844.36e1683c@gandalf.local.home>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-28-surenb@google.com>
	<20220901173844.36e1683c@gandalf.local.home>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
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

On Thu, 1 Sep 2022 17:38:44 -0400
Steven Rostedt <rostedt@goodmis.org> wrote:

>  # echo 'hist:keys=comm,prio,delta.buckets=10:sort=delta' > /sys/kernel/tracing/events/synthetic/wakeup_lat/trigger

The above could almost be done with sqlhist (but I haven't implemented
"buckets=10" yet because that's a new feature. But for now, let's do log2):

 # sqlhist -e 'select comm,prio,cast(delta as log2) from wakeup_lat'

("-e" is to execute the command, as it normally only displays what commands
need to be run to create the synthetic events and histograms)

# cat /sys/kernel/tracing/events/synthetic/wakeup_lat/hist
# event histogram
#
# trigger info: hist:keys=comm,prio,delta.log2:vals=hitcount:sort=hitcount:size=2048 [active]
#

{ comm: migration/4                                       , prio:          0, delta: ~ 2^5  } hitcount:          1
{ comm: migration/0                                       , prio:          0, delta: ~ 2^4  } hitcount:          2
{ comm: rtkit-daemon                                      , prio:          0, delta: ~ 2^7  } hitcount:          2
{ comm: rtkit-daemon                                      , prio:          0, delta: ~ 2^6  } hitcount:          4
{ comm: migration/0                                       , prio:          0, delta: ~ 2^5  } hitcount:          8
{ comm: migration/4                                       , prio:          0, delta: ~ 2^4  } hitcount:          9
{ comm: migration/2                                       , prio:          0, delta: ~ 2^4  } hitcount:         10
{ comm: migration/5                                       , prio:          0, delta: ~ 2^4  } hitcount:         10
{ comm: migration/7                                       , prio:          0, delta: ~ 2^4  } hitcount:         10
{ comm: migration/1                                       , prio:          0, delta: ~ 2^4  } hitcount:         10
{ comm: migration/6                                       , prio:          0, delta: ~ 2^4  } hitcount:         10

Totals:
    Hits: 76
    Entries: 11
    Dropped: 0


-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901174627.27c7e23d%40gandalf.local.home.
