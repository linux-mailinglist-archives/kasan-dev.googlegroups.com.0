Return-Path: <kasan-dev+bncBDAMN6NI5EERBUXCYSRAMGQEW7LZDMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D7B686F4798
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 17:50:43 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-4f00d3f91a3sf15089418e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 08:50:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683042643; cv=pass;
        d=google.com; s=arc-20160816;
        b=r2yWlwaQTeB0Fv4Rwfqu6gz2dASgHgtp6pkheghLsJqF+ubduBgUJCU0cBOw64bQcu
         wV3k8dEbGXKBvbZsgDtYmsvdqBefycB4JZliA5u3hitKrez2+bA8xzaD/mEwY/K+oXKO
         vKoln2iQ4ZZ9AvJwkemzvwv2624URDJLCKjuANtZYkEFEK4I3GObXhyneL6Lg1TFXKjB
         zc7A86pXrrZAyqpqmbRDyLeAeLaH6FZSHWkcHFo5Zj/feOYW6Pg/nYuuwSorfxFZUZw0
         MhBqf5Q1dpfY2m+/3c21GAJkQgLP8fN+at1RpWXQdU5IwtJRCJCz//rNDqL+loCvP09a
         GMXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=34FVsXx7cZ0X0WsyIS6awKQSvJHNtQLaazuj1fQLrEk=;
        b=AaflPlQCEdDxrvyDXnZw99/ovVKe9XQHuRBu0eCkjLiXf1iUWRNZBFBF0Lq++JCy7T
         XamkUtMddknsjgZqxc3WoZC2CkmzvaEl5tX8RlI9Q6q/mRxa/q+g3/PDado848AQWjry
         6wC2WlfsI5B+MxXR/X1y3SW8PFW8eSrk0GNRkHTL6Wx6d9zvZRHR1A+8/0gHWRPUIOd2
         lO3i/goVQ/V0016wWvnH8e+Uh/JHTj+4Oj+l6owsc1xaNpHdzjy2+E11PhA0mJm2ar96
         VF6MFZ9n7MGUSXPsaND8uJYrjDn1XlDS3IAOs9v1KHLmDXbaBmu7ooCdSfpi3+S2ZBCm
         Ffdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Rg36uIn8;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683042643; x=1685634643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=34FVsXx7cZ0X0WsyIS6awKQSvJHNtQLaazuj1fQLrEk=;
        b=S0PHENjQQlMyrfkpICIToPEvjVMecAvHZY3+LPLNkg7w5bbpY7MFeVedjxsheYEksy
         JS+FzypllxP0B57ZHDAYjPy2a46yZ1MgS2OA8F2gAUWyOJRPPGbDGdV1+P6l5sJxSOVk
         NDTT7+W8TGRN2TQ0oxrhXzbe5G4QRu7m28tzf3ieGAnXQUzOT6vA4XRSB0tX7Hh4d1FN
         D6LlbkHdbIKrTp1mazQprzXXnVm83axsRxWOjT0N9XiEKn6sWD9NYOwmiJXR0obi5rEM
         6LHce2252pSwMHryMFtAirBE6A5Le6nfug8pAsUyHbdjPwOuHKvCnTOdKneGVHESHYZ6
         zStw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683042643; x=1685634643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=34FVsXx7cZ0X0WsyIS6awKQSvJHNtQLaazuj1fQLrEk=;
        b=WQosRM9/kMX3GqTTL9NZSLZBv++TMuUGBonWbETsmTGxUQ26ufj1lXsQ4bHKo1hybG
         QwDYfOS16vLz8z3r5ozU75OGmc5UUvMNAZDhT7nlTwPAJ6yy1Ojw4GcvRfdz8jOQYari
         g/ZWzrwDDCqYYQEjfJikSqc7SvIvkIWs18UyputvdOE5OiMEm6Cg3o1h3cOAEGKI0Ub1
         VuMRDqSbfRwp37dY6eVWkhO/OSqhj7zhc2MWSSWpMNkiHgRrIGov7VxB0j08AYdDTCP5
         rX9Zs8rLlki8NsMgDTjmsAT3QqYt7mYReiMWXD9EaErWIfzqdDUySBRLH3Y7ccIj11ga
         XkIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxorD0jKzJzaZEHWGrqHd2AjIqV/gsbC11XA2QZY7CMtToa5O+S
	T2XFAEqHL5HUIsYqyZq2bHA=
X-Google-Smtp-Source: ACHHUZ4EkzjiHWWnwohMI2LnwSRnLC43pAX71Rh61MnxJLuARWg1sG14V/hgHSbvb7xEEwA1sQKRnQ==
X-Received: by 2002:a05:6512:3c9f:b0:4ed:c2d2:8079 with SMTP id h31-20020a0565123c9f00b004edc2d28079mr139529lfv.5.1683042643065;
        Tue, 02 May 2023 08:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls777046lfb.0.-pod-prod-gmail; Tue, 02
 May 2023 08:50:41 -0700 (PDT)
X-Received: by 2002:a05:6512:40d:b0:4eb:1048:1285 with SMTP id u13-20020a056512040d00b004eb10481285mr103413lfk.47.1683042641775;
        Tue, 02 May 2023 08:50:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683042641; cv=none;
        d=google.com; s=arc-20160816;
        b=JH/Td67VBYq1OP8qK3lCM88/atE48aoTRUoB+/465DyPNMzk1UbK+ojZfzPVtgfvHo
         Cl2uKmIHmEaynTakgHo5ZuG9x6t2fjnlreFq9yuG1l1RGVxRVoYTxRMaTZHadW/UL8on
         wwbKhO4Hf1LLXv4ZOhIJ62zMtLHVgsr6BThY7yaguRBRcVYYiXUgEAAJtQ4AOqu/O9Re
         cEJplCbYbimKR9ELJtRvEQflQx0alrYE8jjgdJlPhHumwt9GkQku8lHMk7FR6Y6Eggzy
         sKpGHpLUTWkp/7E6lgGIH9k2ziWQ6hDpy/jA2/3TIDF8iTHajMRwjpFEbVD2ZqD8dNDT
         TroA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=wZImvKcn9w5NAAzZW4fltpVUcvOYAB8X7GMAppUmOCM=;
        b=ePeuWyuaC1O89B48J5h24+drjTf8oFzZgDv0LNtUDIQI4lJ/MPEB57qOpQ3gAgUsNC
         Z967DuXudLsFRnHYo62pdvoKCgU3SqTmgk/07ttb2uLOtLSJeVdsiiSnxdSIEPD9pDCr
         SUAFFfV2FfdzuNQ62pk5V8ZgszytOVHopL/I9ksBOT4rjmVGZhNOKgPhMBQ3GKvNO43k
         u9ePa+ow8DUPEYtv53ZTgCvGlhdioEUojaiMy0DCOnVoHUh5Uehs2f7LMAMp5cScuTXD
         x9IVhaGQB00SGlGws4+Ya5zkoYQUT2h/UC8GQZ0b8dGYMoazdqPuaHS5eOoLAISRDlaM
         q24g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Rg36uIn8;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id h14-20020a05651c158e00b002aa399f4d60si1555861ljq.6.2023.05.02.08.50.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 08:50:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 28/40] timekeeping: Fix a circular include dependency
In-Reply-To: <20230501165450.15352-29-surenb@google.com>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-29-surenb@google.com>
Date: Tue, 02 May 2023 17:50:39 +0200
Message-ID: <87sfce4trk.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Rg36uIn8;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, May 01 2023 at 09:54, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> This avoids a circular header dependency in an upcoming patch by only
> making hrtimer.h depend on percpu-defs.h
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Cc: Thomas Gleixner <tglx@linutronix.de>

Reviewed-by: Thomas Gleixner <tglx@linutronix.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sfce4trk.ffs%40tglx.
