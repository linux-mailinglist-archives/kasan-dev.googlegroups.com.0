Return-Path: <kasan-dev+bncBC7OD3FKWUERBOVF2SXAMGQEX7XLXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EBC185C644
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:59:40 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42c739603b0sf9051cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:59:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708462778; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tab9qUnV3Iyragx2u738ub0iK46J7mdYRqTduO8HMXhqNJcqzXUxIabE43AyIjDf8t
         rJnDEfgk/GknNFRH0WrI3er1qQ8pvtE2c1ZmlcXGslbiBQcMJjpZMG9oOX03lgGd/QwA
         VTW4mMoApZOYzHcLyZGGH23a4ZqrtRYr7+DeQ+XxBTuDEjQHeip1F/AmW2d56cdrMRc4
         CycGp1IwISfTgd2ipiykdJbGh5Sohh402oJ/k+Tea99SNeBMGfO7vPJsaVS0YRz2vt/o
         qSapSx2q3l+rYtBYTWRioU7T8cuNfPIi4PeJtnpyeTNB0D2xeD2nMzcha8MYYww0u1g4
         iLkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NKdX1bzPawNcOpFKzq2RyNrK4AQ2nYEPjWRiCGzzQmw=;
        fh=Xn+Ljg0wi9+EcSLFuq7KMFeyUKR2XO0xGB5p2nqV964=;
        b=dfl0fNNDJtLYXNrovTqFy5TikJfGTbTirYur8HhkZhTAtkxzNId/O4Xd68vzHAjQHh
         TbgrInLDmVAjD4vIWHz4TXyvxyRgGyXPvBX4ZG5il6SFTJrc555odJRZS6MgWnPeC6D+
         BOFGCdTmCVA/JOVF+5kgjPIHScwkGk2lCih7aQd3A5MuZiIbzV7ffrVXGV2b24oYxnLs
         Z8YEarnAZP9WqgUdjPIgmY9L1Z1y7tJHZhi9TNbjqvgsHZpwJfYZYteDydG4U+nrAIdF
         jnwHzaGI9Kjx6sKZ5z5P2iT8ff9dbhZjh/nu667X/6qtSApH8lFx+5WhnIZ68wUBkXn8
         L13A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JMbwKhxi;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708462778; x=1709067578; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NKdX1bzPawNcOpFKzq2RyNrK4AQ2nYEPjWRiCGzzQmw=;
        b=WhudPmJey3xMLDX2vLX6blKD3HCpGkn/ZWvSmIFqIXn1JusDq44qCa0NeBlUql3B1F
         lnFG9YKvhq1yeASL6DAOfLam8TK7UqKN8Z/TdBwRe+mI1tindkaYCKKWbcpCU6z8WdPW
         u/2lnzwiQVQirx7+NG+6OAzeu+MZcIbq1LWjjAR6olsnmIdH1ap6CkioCEfRdZjcGrZO
         ozpe7wKO9GB5uqBz/CO0IkumIrGHWLDdWX31NamW41qrJZ1PR+uDB8gXyspUgusg2vYt
         RBn4ZCQm5eO8yp43rnL4RVmmcrWlrS9upbq6h3hEDOEO4XWVO+edlmMrZndL38oGByJy
         Asmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708462778; x=1709067578;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NKdX1bzPawNcOpFKzq2RyNrK4AQ2nYEPjWRiCGzzQmw=;
        b=q5Ylt8IeeK3JXEhvsSqCxp90pbk59F6SWVYoNjMFvwWjPauKG7vfPzKTg0PDhYHpAC
         8CYPoie56xZg1llxNiglvRIUdWcuhHOvEr750HrE9mc6ksFOCSYF6e5FIs0TYWOvKOLn
         eS84mMadP/tsWve7hqbSqyKjy+KBDwdVW4eyooOLdFEnjSaQ0Ay6thQJ7aovVm+Yrgt5
         Oe18WDJyTo/kC4bu2BewuNsh1xZzwVeBsaNF2N6eAi+1UFFq3JC31I832OgLBh3paCbd
         NIjhmWi9qGNk1g9kqPWBG4iEFtPcvLb1hEQD9Wg/6JNPKL2YrecZHLCSjFauARDHiVJk
         nxww==
X-Forwarded-Encrypted: i=2; AJvYcCWs34dSacfvu9BC6N+QhOuqaK5ZQgguo4O/oANyfoF/CV/DhmmWH9ucGQVswwWq/X/mmadaYFaEWQethgTGZPwRYKmkrEIrOg==
X-Gm-Message-State: AOJu0YwT/SFP2cD9gM5YuU9JW8IqApl29pfAzTbdtz6KJ+yFBxa84k/x
	inI45mV3jlae1b1LOybQfdd4DSY0zCsMkeZOzzQVOw/x8ZTkZU+u
X-Google-Smtp-Source: AGHT+IHv7inIKzxDNBDAH7QRH4qJAr1Gfyxllbp+DFDKmLcf6/2AdSagVVt0g9BLsqduiDej/+07qg==
X-Received: by 2002:a05:622a:1054:b0:42e:1288:2900 with SMTP id f20-20020a05622a105400b0042e12882900mr7302qte.18.1708462778571;
        Tue, 20 Feb 2024 12:59:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d082:0:b0:dc7:4417:ec4e with SMTP id h124-20020a25d082000000b00dc74417ec4els1119042ybg.1.-pod-prod-04-us;
 Tue, 20 Feb 2024 12:59:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9jrlgDJ0kcsZ4aCoRwGZAu48dJ9D0gxrzOrql3fNiOXzLRn9cF5RzqrAOK4i2nxvxE3siQNsnR8pOKkCnzRHBr7SKOv6Act50fg==
X-Received: by 2002:a25:910e:0:b0:dcd:ef35:91d5 with SMTP id v14-20020a25910e000000b00dcdef3591d5mr12572150ybl.2.1708462777670;
        Tue, 20 Feb 2024 12:59:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708462777; cv=none;
        d=google.com; s=arc-20160816;
        b=udpv8MyCaiseIDZYAraR/YKzZYFGdpGjczoJcguZ262P5hwzmV1eYSKzOedbka73bp
         EA5UeTs3wj9QSA9d0YNySBnvpf5fslzIhrPBVEzQCcY98sMujCeczzUacFPh0zPHm4jX
         8gcwllF3eV6fngbWjY4VLhHuW6wfFMdD7AxENlTFUjQVIhCVvSEFV6ftSMJswYXfWf2l
         LdUxDCuSgMTl2I1474Jt8H3YsncSA03Bc5jD8xz5jLyflzgpCl240K9iJiolqqzJKA1N
         oemLR4+UrJYdKwCwA3bgho9NZ8qjcfEz0R5Pp1II0Byh1VLTyHkz3MlX9umErNw33Bui
         VFDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lAWvibZYCLZJ18pHlosxEIJ4ZpAXKtZDbRFFnu5UjNY=;
        fh=KNSqFKjn2QKk1h2mHFTR6/RHRfi8njuP/Iy5USxabXU=;
        b=bp7lAmFpFAHpLzaogAnY6qKFNBSEYkMnyA+aHa7ETA5/BQjYQcnM+Jfp/xBIjr5B/A
         CzoHvidPPXPyC5MyOpN6qb+03otFBlBDPWxSPiJE6QbKdQJrbAVZAnTVmel1Lw8sWfyF
         82/LY4jxQhXTQ8Zo1Mas17JHM8iwGxowGbqZk2UiBaDpMlVf2MaUlPCiMBtu8jbkDc4f
         MWAH4da60c/YF1JuGDVfRWW8IECSCv1lmVcxyBd/ibkbAhOBv8L9jopRk/Xo8WRJXae2
         TMxAyRU6QJ1c4aLLTOug0OTqqFkx3Ss38SiDfc6P0eSBBSCGZzLhyti+bOu6K/2fxkXf
         0MeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JMbwKhxi;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id 197-20020a250bce000000b00dcd162eec7esi1069659ybl.2.2024.02.20.12.59.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:59:37 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-6083befe2a7so25508877b3.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Feb 2024 12:59:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWyKoNZBueTnGAp8WjSfosaSk1uJ+xVpxiiCFHkXRW4dhsecUqk080nOHSs69pIx96cog2KRhq1XS01QZZ7VP/0v6/DggJdR4WSGA==
X-Received: by 2002:a81:7c55:0:b0:607:910c:9cb3 with SMTP id
 x82-20020a817c55000000b00607910c9cb3mr16089286ywc.36.1708462776952; Tue, 20
 Feb 2024 12:59:36 -0800 (PST)
MIME-Version: 1.0
References: <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka> <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz> <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home> <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home> <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com> <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz>
In-Reply-To: <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Feb 2024 12:59:23 -0800
Message-ID: <CAJuCfpFYAnDcyBtnPK_fc6PmFMJ6B4OqS=F7-QTidZ+QtJQx1A@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Steven Rostedt <rostedt@goodmis.org>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JMbwKhxi;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1136
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Feb 20, 2024 at 10:27=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 2/19/24 18:17, Suren Baghdasaryan wrote:
> > On Thu, Feb 15, 2024 at 3:56=E2=80=AFPM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> >>
> >> On Thu, Feb 15, 2024 at 06:27:29PM -0500, Steven Rostedt wrote:
> >> > All this, and we are still worried about 4k for useful debugging :-/
> >
> > I was planning to refactor this function to print one record at a time
> > with a smaller buffer but after discussing with Kent, he has plans to
> > reuse this function and having the report in one buffer is needed for
> > that.
>
> We are printing to console, AFAICS all the code involved uses plain print=
k()
> I think it would be way easier to have a function using printk() for this
> use case than the seq_buf which is more suitable for /proc and friends. T=
hen
> all concerns about buffers would be gone. It wouldn't be that much of a c=
ode
> duplication?

Ok, after discussing this with Kent, I'll change this patch to provide
a function returning N top consumers (the array and N will be provided
by the caller) and then we can print one record at a time with much
less memory needed. That should address reusability concerns, will use
memory more efficiently and will allow for more flexibility (more/less
than 10 records if needed).
Thanks for the feedback, everyone!

>
> >> Every additional 4k still needs justification. And whether we burn a
> >> reserve on this will have no observable effect on user output in
> >> remotely normal situations; if this allocation ever fails, we've alrea=
dy
> >> been in an OOM situation for awhile and we've already printed out this
> >> report many times, with less memory pressure where the allocation woul=
d
> >> have succeeded.
> >
> > I'm not sure this claim will always be true, specifically in the case
> > of low-end devices with relatively low amounts of reserves and in the
>
> That's right, GFP_ATOMIC failures can easily happen without prior OOMs.
> Consider a system where userspace allocations fill the memory as they
> usually do, up to high watermark. Then a burst of packets is received and
> handled by GFP_ATOMIC allocations that deplete the reserves and can't cau=
se
> OOMs (OOM is when we fail to reclaim anything, but we are allocating from=
 a
> context that can't reclaim), so the very first report would be an GFP_ATO=
MIC
> failure and now it can't allocate that buffer for printing.
>
> I'm sure more such scenarios exist, Cc: Tetsuo who I recall was an expert=
 on
> this topic.
>
> > presence of a possible quick memory usage spike. We should also
> > consider a case when panic_on_oom is set. All we get is one OOM
> > report, so we get only one chance to capture this report. In any case,
> > I don't yet have data to prove or disprove this claim but it will be
> > interesting to test it with data from the field once the feature is
> > deployed.
> >
> > For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> > becomes safe and the only risk is to lose this report. If we get cases
> > with reports missing this data, we can easily change to reserved
> > memory.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFYAnDcyBtnPK_fc6PmFMJ6B4OqS%3DF7-QTidZ%2BQtJQx1A%40mail.gm=
ail.com.
