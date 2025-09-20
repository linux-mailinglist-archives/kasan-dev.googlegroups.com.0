Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUBXLDAMGQEMQ4DZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 174B5B8C57A
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 12:24:06 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-327dd4d160dsf814199fac.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 03:24:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758363843; cv=pass;
        d=google.com; s=arc-20240605;
        b=kGboTH0Hofahpk5K7GIenACvVC4XGJufsRfIBKAo6mVsYJoGqd33hV+MMX6YiS383r
         JobAZH4xUwc9AUphSFDia8xe/CoPbnd8TZZuBdkDux/ATQ7DSp1GKstmY2XwaACz8vyT
         GEP3cRXuqTI1wZ0bA8lNYF2QUanTAM6eQf/9DVRAuetasupU7PI45wNWij8X33D6H283
         B1QJ5wHXeZD1e6Ot72MpP7woe4V7+Tk7aVB1EWDQRDtaLqejBcW387TIp//qxvyakNXs
         p7FhQd0CYKiTJqeQulO8Olp8yQwKBqGw1Ej16UlLM96BK7MLBtXyqMRh0ipSoXPRAmgN
         OqlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QzKA+xieip6FWND4o59fFM+w1ZIDJc2o9uVeV3O7sKM=;
        fh=MUHNIoV9sfOyb25hjoGFFzcEK/A2JnOYPz0qHuOUeUg=;
        b=WmqqFETHVvG1reoSaMaRi2iGtUY+8CTpyRXvzJMRcCc31/rpE+6t6JGmcMoiaKPHL6
         KQIUPrkGja21YMRyfsgXqxzd8dE8SOIqVJGp7I5DVk9bWQTzOTg9gWxY3bHLbotnT6eE
         7ZXx9o7TtoAoyZXTux/nvLm63nIPGg2sr8yaGN9Yeqw71iOrZ49z249rFRMW9v9qyVGc
         3hN0ec+dOjZne5jyXoMv0nRmAheEaRgwOiQrSYNJ4WlOeFEscVUR5Y/qjV/1KVdmgRCu
         sNl3GRZiaomI0NMz8uQSJobFoXwQG2QkUgVBqI1vZrI1h70IMuLsTC+EGRQHjOnuq4ia
         8ioQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="hg/wjsyz";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758363843; x=1758968643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QzKA+xieip6FWND4o59fFM+w1ZIDJc2o9uVeV3O7sKM=;
        b=hVAfy2WiDbXWb5T5fU+aW/6hMwvFH+F03RRLypHDFfjKe1/AU8ubv0edhAU2Y6jW2V
         HSFIqRCD9o91sT2Hk+3RsqN9yOFC7NR9o//1M2+BkbB1T/iY4lN7TRS55K4eAmdbr2IT
         gt6niD0OB2AMuAMNAstXYVb4uSBJuNkob9LPFHM5RKr+Tzkj9CHSKE944AblFCPNGDX9
         7VXLiny8PhkXfgBFIglowZsqbGYfmZPsfLtQZZPL98fCQ/H3X8tqc/z7WlP+53ue/4Pa
         +bMASjrmcR0QIs8Hys99r1QM9j5EyfI+qDhsXXvquAU6tABELr7LDu4OYqK9+thvKbuE
         082A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758363843; x=1758968643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QzKA+xieip6FWND4o59fFM+w1ZIDJc2o9uVeV3O7sKM=;
        b=ZQvAbWSkJ6OD95Ce8D5/6+P4WmZEaAGlXhqnB+kS7/70x+m2KYY9JAiKKh+HFv2EAS
         Wgv/tM/KngV6VxIBy4l6Xd7FZWZoJNvZcs8Vgy8KHrAETn6CxM0LMKcm/pGCapME1xma
         69htjB/VEWwIwRA2LQxtPng4vNTieIF/+02otD+nQ9rqjI8jwuYZO0biqUjgiQrmUV7P
         gzDv0MV1+iSrv6sKa5ZapmXrzOvfjvC8gTK3S4SRMs3uMB/3DW5royTvXrqmulZjMHcO
         oCEqLU13yW0Lxqyn9ue/NfTZSatSzr4Er87+rwIWBD8fN/tVYEf6IS3FsmXgSa0EVaKW
         thpQ==
X-Forwarded-Encrypted: i=2; AJvYcCU99qy8EOwP5RfnsGxf+8AZIVrKc5e8D66MymgImoW9R4bihvzoLG+0AHC6bMWOgOJg3cyNkw==@lfdr.de
X-Gm-Message-State: AOJu0YwjbfsEBCYVja4YtBzIQSb8a69piJhc/ILfnJQ0IJRrBhrydM0U
	J0aomJf4f5eEzA62j5Xf50El5ws0sDNIP3oyoInMSS3iQ3XHPO+axZYB
X-Google-Smtp-Source: AGHT+IHK76Tq/PvogBzQHT7MSkvILUKXMjw7H63oZ5eEoLMADDJJxD2cUQmQ54ueF4NhYL1pZOqg3A==
X-Received: by 2002:a05:6870:b629:b0:315:9799:3034 with SMTP id 586e51a60fabf-33bb25f83c2mr1787257fac.4.1758363843226;
        Sat, 20 Sep 2025 03:24:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6kBozREE5MlHRKAQmZ/kqDdOlp7jFXlHhp8ReiJp0/tQ==
Received: by 2002:a05:6870:a34e:b0:315:531e:fdba with SMTP id
 586e51a60fabf-3370155cb0els915836fac.1.-pod-prod-02-us; Sat, 20 Sep 2025
 03:24:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmCZQH8QMcSw2yG5UzGKhqTv6MIg7B6jxvrarujICJa/OQ2tBux771VI8OHfFYMzhLkAvg+MwM2A0=@googlegroups.com
X-Received: by 2002:a05:6808:1388:b0:439:1193:fd19 with SMTP id 5614622812f47-43d6c2d56ecmr1624522b6e.47.1758363842003;
        Sat, 20 Sep 2025 03:24:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758363841; cv=none;
        d=google.com; s=arc-20240605;
        b=UTOFSfDHkGYkqMlggzTLnnhHyVZHh6JJ8p5wEIJ5o1c+ZwpfXN4dnzbJkAwyvjVWcT
         Bg71yvm7npeLgtwvCalg8iXrf9IhoUq/TlO8ld9SaGbdj62MH61LdFQQfF1KIg28wn68
         CZyLXOlBa4gj543YXWUo6aal/T1au90A5ek0H7G4NbXNZi7ZiVYHHeEd06xL/MWmpwKC
         HkyzFM7+sw0qQByX2Iz9zn9TZkR0h6hbNckzZgB7Nq0uVh9nCFPYnQGeEN6H2R2cFv7B
         z+tddplFqRtjCDeyim7Vdp+wPHlb+f8jhwHkeiB7SQls/wHBjlhA2EnYPR9BZMb1FjYB
         /lJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+hZhQHzO6iaBCv+wcIWwJCdyKEWcJ4Nfwc3KoJ0ZPEA=;
        fh=D7qNY1WaDnp+hJvYeX8NvB7rZomme19M1uQuw0W9mbg=;
        b=N8szwOXr5z8o1Fe4SJDSj/xBb7qdxu5RPJWV+nfOzOgffDsEvWlsQn8awrwN/gZJVG
         3RDHbrSxqtoapr1JqoRiOpr23w/bbkKt2DuHTOEw2hoRizlD951/KgOLL2pgKl5gZOKm
         jO4nHuDBtNUiFZ6LshTJfHmuhmxaQr+8cTOklakH0C+FffeV+trL+AXJ9b8jho4daGVw
         vm7suI+SI78DEYbVav/VR2WJ6EG6l8psaPTFQ6UwMz74b1TZzfXiu6JL3Z5OGcBUvjOJ
         T3g7QjKxiTybd7J8L0gqqQABih43FaaeSdUBLZf4XjDxe02XJRLtO2ulJ5KvJVCQLYZl
         buww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="hg/wjsyz";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43d5c7281efsi200707b6e.1.2025.09.20.03.24.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Sep 2025 03:24:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-77796ad4c13so1909070b3a.0
        for <kasan-dev@googlegroups.com>; Sat, 20 Sep 2025 03:24:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUiyjl6bGOdoOzpAvZq47HrtjqRuqEnAqwXz/Yv+uqQ8EmSP9eHbQ3/AaKst3rV2U4qq3Z4NZY2+M8=@googlegroups.com
X-Gm-Gg: ASbGnctuUOXdVg+VYqJ3pV/Te/zGVfHE993jvzNETEhw89Jyr2LPwWlITzieiCyy+FL
	qxuX6LQLuAdThM7qrzMeMFlJy+/hVPsqtBSeVVZa8Sj4w/SmEMlHmjv6Eg06tns5C6Pk1yKRToo
	Ls8IynTWXm//YHTWUZcuIq64Bi4QzFotVvqQKqTOrmBR0z4Coro0u78e1YtzgkbXua1CAH1e+na
	VmcO92a8TmiLU/de5Zy9oDnyaRtZbCS56PopA==
X-Received: by 2002:a05:6a20:914d:b0:27b:dcba:a8f3 with SMTP id
 adf61e73a8af0-2925f76be25mr8434118637.15.1758363841077; Sat, 20 Sep 2025
 03:24:01 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de>
 <20250918174555.GA3366400@ax162> <20250919140803.GA23745@lst.de>
In-Reply-To: <20250919140803.GA23745@lst.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 20 Sep 2025 12:23:24 +0200
X-Gm-Features: AS18NWAyC50-QQYD_wTUETPBlkphWLV8M7F-miEs8DZ-lOTnj5WEfB5uYr0Ax6s
Message-ID: <CANpmjNO2b_3Q56kFLN3fAwxj0=pQo0K4CjwMJ9_gHj4c3bVVsg@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Christoph Hellwig <hch@lst.de>
Cc: Nathan Chancellor <nathan@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="hg/wjsyz";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 19 Sept 2025 at 16:08, Christoph Hellwig <hch@lst.de> wrote:
>
> On Thu, Sep 18, 2025 at 10:45:55AM -0700, Nathan Chancellor wrote:
> > On Thu, Sep 18, 2025 at 04:15:11PM +0200, Christoph Hellwig wrote:
> > > On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > > > A Clang version that supports `-Wthread-safety-pointer` and the new
> > > > alias-analysis of capability pointers is required (from this version
> > > > onwards):
> > > >
> > > >   https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
> > >
> > > There's no chance to make say x86 pre-built binaries for that available?
> >
> > I can use my existing kernel.org LLVM [1] build infrastructure to
> > generate prebuilt x86 binaries. Just give me a bit to build and upload
> > them. You may not be the only developer or maintainer who may want to
> > play with this.
>
> That did work, thanks.
>
> I started to play around with that.  For the nvme code adding the
> annotations was very simply, and I also started adding trivial
> __guarded_by which instantly found issues.
>
> For XFS it was a lot more work and I still see tons of compiler
> warnings, which I'm not entirely sure how to address.  Right now I
> see three major classes:
>
> 1) locks held over loop iterations like:
>
> fs/xfs/xfs_extent_busy.c:573:26: warning: expecting spinlock 'xfs_group_hold(busyp->group)..xg_busy_extents->eb_lock' to be held at start of each loop [-Wthread-safety-analysis]
>   573 |                 struct xfs_group        *xg = xfs_group_hold(busyp->group);
>       |                                               ^
> fs/xfs/xfs_extent_busy.c:577:3: note: spinlock acquired here
>   577 |                 spin_lock(&eb->eb_lock);
>       |                 ^
>
> This is perfectly find code and needs some annotations, but I can't find
> any good example.

This is an interesting one, and might be a bug in the alias analysis I
recently implemented in Clang. I'll try to figure out a fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO2b_3Q56kFLN3fAwxj0%3DpQo0K4CjwMJ9_gHj4c3bVVsg%40mail.gmail.com.
