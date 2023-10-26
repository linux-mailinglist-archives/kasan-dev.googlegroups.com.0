Return-Path: <kasan-dev+bncBDAMN6NI5EERBT7B5OUQMGQEI45LA7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 280297D8C0A
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 01:05:53 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-507cc15323asf1572449e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 16:05:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698361552; cv=pass;
        d=google.com; s=arc-20160816;
        b=h/5OJS/qLXuIlj6wtc0EoVIC9pRo0ZbZhCZbFgnqIp7huTtw37qTuYDCUJYJPt+1j2
         VmKSqDYXYZHzAcUx1OCU/SFRiVcSTA0wGEF4ZFS35khbitn0qfUvR2i0o9WaAy87mPAg
         6iizzmupS4uZh2yAv13Jm19EHVE/6sIwMQi1g9Aw34OWfBOsBBKsj88F9CTFhkR/V9Bq
         uVF2PbcF+fR4+yNEsBtW2758d/WY589Jt7VX4Gu1FJteTVvsjT0WST7NNR75kyCe4W0O
         6f/Zuxo6Ruz6f5m5nuF8ZrLnKalyDXUG9wtfchhz8ztPqvxiLxSLfOJgLMrmcHKpHGY1
         nsZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=exjRmuQ0zA9Bi2nZEhlFWNrfMGzwPeXznEcHN1wlFEk=;
        fh=04z59ZoKPgBZcXBvtehr2+PzA8TdQjB3urblmn+Zq7A=;
        b=lArFa06/U1lA0KpEdHzn7/SGSGATk9fcpMQk7N3GnpsJLX5E+Jx4nE0mbEqBPah0eM
         FcSEXPNEpM6snAsiwUWlz4Ksxep5XwLX6cUHNIjlCCX7FHzkgCNHstMgNZZJKHNf0ZwZ
         R95u1Zwq03Li08hVmGUI3VKlDuylxnoCQwitSEEe6Mw+aIZaRxHCMHdJvm4C6UixWC3k
         Mmn/oui0qE9VdmYLAusMLhyYBJtB5gANmQPf0qiJYyQ5h/X4McSk/jSGR8z4/JdIJlNZ
         5Dm6ynixcuq2RrP6xHefYwb/lFrf4gdNYD5CNPd+7LjnRTPFtVClI8m1nyfQBIsGtyVO
         vmtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Eb1gIXVa;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698361552; x=1698966352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=exjRmuQ0zA9Bi2nZEhlFWNrfMGzwPeXznEcHN1wlFEk=;
        b=MpzmIPyrV3+g3JzrdqK7fVd/kkAv0IGU5Xa0KDoSgJUordRNSzXaEGlIO/CniqJk3r
         XPxWoMppdo5t0E9ApjegWvpd+FIaFDEzzlfAQ9GerNCCegb0i0RIE8LMpwSvPJyWWxa5
         DqTlaQKY4V0SMLvJ6Qsk0DFnl32mmNgRBz7PtenxlZDAe+964LdVlDs/ZSjB4JbaOVg8
         zysrGnudNW/mm3lQARSrO/rihMZ3mJc+iD/aqSrxrc8PJtSTDwE8JA/+749I0rvNAbHC
         Hn+/WuowfyReiDcTgY9M4kqDdVC0v60DsQ5YC1zYNOQgaH4Lab/Ef0M6YF78Jqz5ml2v
         yKWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698361552; x=1698966352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=exjRmuQ0zA9Bi2nZEhlFWNrfMGzwPeXznEcHN1wlFEk=;
        b=wOvBQTxvCQnmI2mK4w2yXYzyYCzyxG92JolPR2dsTAgz9qRQzE/rHPq+SPFXNgFnoR
         e2ogZVe1nQeFaVBAreMEfRT4t44CHCNq1DQ5nDEDm5YNybtsVt9tllrm3VWHkmbvtkNH
         htjpmz93N7imISkudfSATb5PwZhCNJ9Gl4HMavbiIaYe2hb96vSmlMAfZkS1aAo+Dqr2
         DfIrwEUHOrD7Kzt9u+Jv9fNFnHI9vfBl1Gn6kUZ2Ra/O89gyYZC98dPtbU3t4JdT2OLr
         sEvL+qz6w8jAiMb/I8NbGRMfpj77Eg1UI1bqfWbYpvUngy4AJlTkTMZ20i6P8Indx4ca
         JMpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxW04V40UZjcQ1x36ItFrzGANvQywtWZtyMzal43LROy9W+k/hs
	aF7JsnnHwcy3v7g+KnuCY/E=
X-Google-Smtp-Source: AGHT+IEb2Xwy1BA0+Wc/I4iBX/5TKg2wbYnqttynShplikpW0/OJZYzhxYszc/F1yrvzwbx7U4rfPA==
X-Received: by 2002:a19:5508:0:b0:506:9304:570b with SMTP id n8-20020a195508000000b005069304570bmr526293lfe.14.1698361551633;
        Thu, 26 Oct 2023 16:05:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c8e:b0:504:1c05:94aa with SMTP id
 h14-20020a0565123c8e00b005041c0594aals347561lfv.0.-pod-prod-06-eu; Thu, 26
 Oct 2023 16:05:49 -0700 (PDT)
X-Received: by 2002:a2e:b617:0:b0:2c5:f54:2477 with SMTP id r23-20020a2eb617000000b002c50f542477mr672639ljn.40.1698361549547;
        Thu, 26 Oct 2023 16:05:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698361549; cv=none;
        d=google.com; s=arc-20160816;
        b=JhkvVq1GEA5edvxLJWukQOfGrzPdFJxWNb3U6kj0r9EKZ5NWjZulSbBiAsMxIaLR89
         fogAMlYeaQmff0Mrrw+ySa/IOEkAmHZZqBAw48pN2gxVB5WWSv9Ynj6WPRjuuEj/ayG0
         rCn772D+wzLdWEq0E3Vz1VJL9Qi6b3bBRQoDoJO3cZsuEw5KSBrUxDzhVOIB2/aQ+xNS
         aeQV2meI+TJ0WNsznn0lNh1OlE4Q7P3rStpZqNhUBgWQ1FJ3qQhYfLEfYzDT+veoUMxR
         pQSCplhHBiI8X0orNyi8KoUD168KTrnUdjexN46N4zYJhIzoCXTEltOrIKw1lbzsY+Kc
         isiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=301JXjESu5nnVpLjEelVyjL0FjP4Jn3OGJNIUK28IQU=;
        fh=04z59ZoKPgBZcXBvtehr2+PzA8TdQjB3urblmn+Zq7A=;
        b=gLQtiWZVwZjXr+qH2dC/F2F+ZtqYoHZ4PnAJ3RrCMu3ufs/ISSpV3zUQns6dt8VDQs
         eytjRvcS29SgoC45umqs1znI6PCO/paZNDeKZeSYamG3zjVIMeDmM94mgwxT6gIVMNw3
         Vd/YAIgnv6jOSvM04lqtjyRHpejvp/5iNy2mXOeXr6o5B8l/qM3nYqxp75TF6A+S5g5j
         CzS6rkKA6YMwJc670Oc4EF75lWaaZxvr83/bgdsAk8eC5YbgOstI5ORJPLeFKioNSdUJ
         xQMANyuG2aPsvpZYYWU7B57Av9q2AubhoQkDtOg3CC1J3crMm/A5Iq9U2Fq2/CMv9+9l
         6quw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Eb1gIXVa;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id j15-20020a05600c1c0f00b00405c7dd428csi247158wms.2.2023.10.26.16.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 16:05:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
In-Reply-To: <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
References: <20231024134637.3120277-1-surenb@google.com>
 <20231024134637.3120277-29-surenb@google.com> <87h6me620j.ffs@tglx>
 <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
Date: Fri, 27 Oct 2023 01:05:48 +0200
Message-ID: <87jzr93rxv.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Eb1gIXVa;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Thu, Oct 26 2023 at 18:33, Suren Baghdasaryan wrote:
> On Wed, Oct 25, 2023 at 5:33=E2=80=AFPM Thomas Gleixner <tglx@linutronix.=
de> wrote:
>> > This avoids a circular header dependency in an upcoming patch by only
>> > making hrtimer.h depend on percpu-defs.h
>>
>> What's the actual dependency problem?
>
> Sorry for the delay.
> When we instrument per-cpu allocations in [1] we need to include
> sched.h in percpu.h to be able to use alloc_tag_save(). sched.h

Including sched.h in percpu.h is fundamentally wrong as sched.h is the
initial place of all header recursions.

There is a reason why a lot of funtionalitiy has been split out of
sched.h into seperate headers over time in order to avoid that.

Thanks,

        tglx

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87jzr93rxv.ffs%40tglx.
