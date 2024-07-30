Return-Path: <kasan-dev+bncBDK7LR5URMGRBZFPUS2QMGQEDOHDE4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id F2504941A47
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 18:42:13 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5a7661b251asf4893529a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 09:42:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722357733; cv=pass;
        d=google.com; s=arc-20160816;
        b=hUksSsLFwxDH+izuelb+wyeUU2EqK0YxzArkeil9yvtlqd1Q27lCEKAjG/ykwd2qNl
         SIhyfF9lfkjgOOQoDu/GTCDY9QMqcoi0jdpt8z40DJ3avXdBnPXlRMUVYebOBppsEOWB
         BeolhSXlAaX4fcLIcTv7Za6aLVAOrSBINnoB7Zukz+BnqaP/xvynLcSQNtLaA+ZDiIZA
         DJp4toV0Mazmv3sUjiSePoTHH7mmG1+DfuOcJXbGchXvDA6aGYN3FHvXNfaWxB7UOaxi
         4xBYEWH56L6J2RRe8P6M19wd7ROgCP6oLWVD2pxF5DILYmvGlpLiuYPbciDqX4WmXAXw
         cbew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=GSgCYJi7kmQ4XPDBurgvhvoEQYEccSQnvd2NkKpA4UE=;
        fh=HHqvcAdHTAUHyndwr62ZvkFVYbz1EGwWG33N/1MwyXI=;
        b=0hXelsSzQH6/rdffb0py+UNrUWP7G/cJMgzNVFBDNx8hNQp7IvZuJ2/ccOu/bBMrnY
         mmth1rSq4VAuffjMkbIp9Vg4REQp3SpQyYxvelDn4Y+5idSxQbz0KXT5HmzOWNO1pEdS
         jfgNByNiT8LnYjsVHhduq90Pct8EVFu1qIFO3be2JHgYwHSCIsiAEuQsEKltelBPc5ub
         /tcpezuX/D9XTSX45ysd4C0I09opDIt7dIOhR1XhmtxYhg+QssLO1Zu8s7G7b3Y807H5
         XlELFOcoK+1dQbKPuOS/s17EOtQDSNu2h/QsNJzhk0vZgSsBfKBB8s5M8Ge9JjP0Ha18
         VExA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aWntPaXF;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722357733; x=1722962533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GSgCYJi7kmQ4XPDBurgvhvoEQYEccSQnvd2NkKpA4UE=;
        b=CgUghRLmVWt9uIi8wgqeH6KSn6uHPHSCcMd6RpIxC0LyFHYaZiLCkKnuhTfMGq6+ZV
         0zAjEZnCP9hEB2cxJxE3rolw7L5T6Bpfn+NKsTwTDHO0boBmETm8G6QFelHALI2oPxBz
         iE4RcCpdvMa59f9LvX4AWCqFOFX//knJvWrYBZmlMCogOawIqGGT7j9x4QWQnFc+bPnC
         AQAaB8xhK3LmXtR6sFCMaTuGqMokmQesr1bwzI2PrlhBhMC6BTJDcQM+iwe6QhmZbuXX
         vrdtXag7jFfXVjK58qiImCMuWDNFgp33m2HQtuX55aHAidERf1twNFQSg7CgiKAWmrx/
         KYvA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722357733; x=1722962533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=GSgCYJi7kmQ4XPDBurgvhvoEQYEccSQnvd2NkKpA4UE=;
        b=kWr+gM3ZU36LKC8mLOOxkLIBKNpEhK74+8XK8LNtHmyfGr3mAdgL5p2TbJEPPpc3c+
         IL7WPBYN7hnf1RyY4dfzbqLOJLy+teQ/S8kRxILjryDQQzwUFkro8XAisOT/IWp5TuV4
         aO1JNuqA3xQf+wFB22IWEBXGgdaVSH976/Wj+BRvuUfDp3uN9CYDiAe5Ee+H88yd2PAr
         lmEiOKrYWwIjg0cROfcQhae4C0/5o1vD8EV6V8r2ivRV+5p6QEGdr9Q5IJCZx1sEedPT
         yMPVD0j5hNA5flTJwjYZXr3ym6yRHdc5zGX849mRiwVDLrERhsagdjHvMHaFTv7D0r+f
         q11A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722357733; x=1722962533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GSgCYJi7kmQ4XPDBurgvhvoEQYEccSQnvd2NkKpA4UE=;
        b=ugJVBWjrQvZTLYtLsJoOivEiNkIrQx2+0/yfBNaewjj7DTb5fT7Y4hn0lQYgBqwhCO
         p3i2zmC1FiNW7sHxhKgXx6EB71wzuiOsYObnGp+z9FPMe3LC6tyORnvgKkgOJbVRhZoH
         RjgoWd0pnFzDZAOylT11I1wrjPoCdCGkjFjl5qTbPR+N2ZCg73ScjUxbgXxknM4eAj2a
         vW0oQAZTp1MhNVnW37WaEI/x+KTTC/7BwcQBBdXTBZ8Jb7ghhzoKspPswgXbeuCgnDM2
         v6GJ/pBVQCsJGJFvApBuVZl2PnTNx7tQ2M6/rOo3+51yjqbBxFA+XCQc/pEBTzOLRXm9
         lPWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVTHlKxGFSvwlxDCsxmwwwbDRHJLvSvWjkvHAzzgT+24PCjQC+1tfQmCZsNp79KUJQE9w9gpQFzIj35cQIkRpthAfufgpCbQ==
X-Gm-Message-State: AOJu0YxkdxeeQLDSnRzpaaK812xiLqWpJEImUCZtIxulqXPRZVBixJSG
	Ee2HZtF6/jw94QWFFQMJ25mJzAO2MMHeDC4LF/y6OTem8Dh3WrBA
X-Google-Smtp-Source: AGHT+IEK9uh4TAc5zIBUQ97VognTgI/2zaZDsDJttnGrp0VIxhhf85bGdE4slpBtr6xcQU5G8Yfmqg==
X-Received: by 2002:a05:6402:1e93:b0:5a1:39cf:6ac0 with SMTP id 4fb4d7f45d1cf-5b0205d6873mr8674997a12.2.1722357732912;
        Tue, 30 Jul 2024 09:42:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:538e:b0:57a:a655:87db with SMTP id
 4fb4d7f45d1cf-5ac0ce088cdls2330472a12.1.-pod-prod-09-eu; Tue, 30 Jul 2024
 09:42:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZuG7W+3eWdN5FdPcIu9SkkHrE8/hEaJLPRR7TZY0xt8sJyF+4MsJAXMm8DzKpDKokBQPXgc4H2c5NhRibwXnh2H9GesmDCliijA==
X-Received: by 2002:a50:d659:0:b0:5a0:e4a6:b3c9 with SMTP id 4fb4d7f45d1cf-5b0205d5d69mr7116494a12.7.1722357730784;
        Tue, 30 Jul 2024 09:42:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722357730; cv=none;
        d=google.com; s=arc-20160816;
        b=fJ0NwJAfE1g2s+mFwWOf9tgCOubvdBdFJbIuF+t7DniiPAuM3CEURcqKS3qfN/kAK6
         zkbGTQlQCUsCcO+fiX54CfCU1yEgosbiiC057PIjT0SAVBXD6DyGHawSJ7LKBToJ0uHw
         yEOqkig7kDruVVF8r+9W5ioaMWPaX3NZhwB038ekiHUyJEdBAzFo5zCSzX2roFqiTTDI
         DVsAjqCGglUwbm3dbEQAaD8Izc4e3y6mSBFdY9ekjc07okZNUaPeUFy/y26XU0QF6+g9
         cv0fwWfOCkt8wH+MuP7MiIHcenMvqtndFuWtRRwoe6gNnxLwMqidFUq/RSPVo24J9vZv
         Y8bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=xPM0aMJJv5fPv90OOd8ioocukIL23WeQ7CLJAnS2lW8=;
        fh=nQJDhoyX7ThjRbkxrlnkxpB9b2uBAKrbYPzJM8Ohuvg=;
        b=kPA1U2sii/1tvUU++0SKq2Up1YPu7evXgHPfDfT+V3T+5TLYIrn/wEJoaxL3K9Yw7k
         LugXfxT+1iBIbMwBuXV8TOUAsYnHRvmi/nFLdfhv2Ka8WAR0JAZV2q0uGECooc5euHDg
         WRubw6mJ/7Tf0jcswxYgsLaaS2h17g4PinVGfEMVbEsLReXCyslVrVC9MlI+wMgXlp7p
         jIPAPpDPCEpgU2n7qcAxN9W9hD3WoJu3+03N5DboZf7Bu0fIVyynl6QSmJPxeVkUM6ad
         4jKagZRBMDA+cqZgrSjAwr8aE+xRtaZGi7+pNlh2I7k7I+JTUseRVrtsuSvDpMlattap
         rdfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aWntPaXF;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5ac63b5639dsi337095a12.2.2024.07.30.09.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 09:42:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-52efc89dbedso6103368e87.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 09:42:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXCUBL+KB3O62YmhSQFw4krn+VlXa9xLuzLV03eW1c3jEX3SjUijm0F6l+PeZvyygZ4sRvywuHYcJdzy8GRHFj+7IqO0Ri8mfwZTQ==
X-Received: by 2002:a05:6512:1cf:b0:52e:9ab9:da14 with SMTP id 2adb3069b0e04-5309b280728mr7253046e87.31.1722357729826;
        Tue, 30 Jul 2024 09:42:09 -0700 (PDT)
Received: from pc636 (host-90-235-1-92.mobileonline.telia.com. [90.235.1.92])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52fd5c19579sm1939593e87.182.2024.07.30.09.42.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 09:42:09 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 30 Jul 2024 18:42:06 +0200
To: Huang Adrian <adrianhuang0701@gmail.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, ahuang12@lenovo.com,
	akpm@linux-foundation.org, andreyknvl@gmail.com, bhe@redhat.com,
	dvyukov@google.com, glider@google.com, hch@infradead.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, sunjw10@lenovo.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-ID: <ZqkX3mYBPuUf0Gi5@pc636>
References: <Zqd9AsI5tWH7AukU@pc636>
 <20240730093630.5603-1-ahuang12@lenovo.com>
 <ZqjQp8NrTYM_ORN1@pc636>
 <CAHKZfL3c2Y91yP6X5+GUDCsN6QAa9L46czzJh+iQ6LhGJcAeqw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHKZfL3c2Y91yP6X5+GUDCsN6QAa9L46czzJh+iQ6LhGJcAeqw@mail.gmail.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aWntPaXF;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 31, 2024 at 12:27:27AM +0800, Huang Adrian wrote:
> On Tue, Jul 30, 2024 at 7:38=E2=80=AFPM Uladzislau Rezki <urezki@gmail.co=
m> wrote:
> >
> > > On Mon, Jul 29, 2024 at 7:29 PM Uladzislau Rezki <urezki@gmail.com> w=
rote:
> > > > It would be really good if Adrian could run the "compiling workload=
" on
> > > > his big system and post the statistics here.
> > > >
> > > > For example:
> > > >   a) v6.11-rc1 + KASAN.
> > > >   b) v6.11-rc1 + KASAN + patch.
> > >
> > > Sure, please see the statistics below.
> > >
> > > Test Result (based on 6.11-rc1)
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
> > >
> > > 1. Profile purge_vmap_node()
> > >
> > >    A. Command: trace-cmd record -p function_graph -l purge_vmap_node =
make -j $(nproc)
> > >
> > >    B. Average execution time of purge_vmap_node():
> > >
> > >       no patch (us)           patched (us)    saved
> > >       -------------           ------------    -----
> > >                147885.02                3692.51        97%
> > >
> > >    C. Total execution time of purge_vmap_node():
> > >
> > >       no patch (us)           patched (us)    saved
> > >       -------------           ------------    -----
> > >         194173036               5114138        97%
> > >
> > >    [ftrace log] Without patch: https://gist.github.com/AdrianHuang/a5=
bec861f67434e1024bbf43cea85959
> > >    [ftrace log] With patch: https://gist.github.com/AdrianHuang/a2002=
15955ee377288377425dbaa04e3
> > >
> > > 2. Use `time` utility to measure execution time
> > >
> > >    A. Command: make clean && time make -j $(nproc)
> > >
> > >    B. The following result is the average kernel execution time of fi=
ve-time
> > >       measurements. ('sys' field of `time` output):
> > >
> > >       no patch (seconds)      patched (seconds)       saved
> > >       ------------------      ----------------        -----
> > >           36932.904              31403.478             15%
> > >
> > >    [`time` log] Without patch: https://gist.github.com/AdrianHuang/98=
7b20fd0bd2bb616b3524aa6ee43112
> > >    [`time` log] With patch: https://gist.github.com/AdrianHuang/da2ea=
4e6aa0b4dcc207b4e40b202f694
> > >
> > I meant another statistics. As noted here https://lore.kernel.org/linux=
-mm/ZogS_04dP5LlRlXN@pc636/T/#m5d57f11d9f69aef5313f4efbe25415b3bae4c818
> > i came to conclusion that below place and lock:
> >
> > <snip>
> > static void exit_notify(struct task_struct *tsk, int group_dead)
> > {
> >         bool autoreap;
> >         struct task_struct *p, *n;
> >         LIST_HEAD(dead);
> >
> >         write_lock_irq(&tasklist_lock);
> > ...
> > <snip>
> >
> > keeps IRQs disabled, so it means that the purge_vmap_node() does the pr=
ogress
> > but it can be slow.
> >
> > CPU_1:
> > disables IRQs
> > trying to grab the tasklist_lock
> >
> > CPU_2:
> > Sends an IPI to CPU_1
> > waits until the specified callback is executed on CPU_1
> >
> > Since CPU_1 has disabled IRQs, serving an IPI and completion of callbac=
k
> > takes time until CPU_1 enables IRQs back.
> >
> > Could you please post lock statistics for kernel compiling use case?
> > KASAN + patch is enough, IMO. This just to double check whether a
> > tasklist_lock is a problem or not.
>=20
> Sorry for the misunderstanding.
>=20
> Two experiments are shown as follows. I saw you think KASAN + patch is
> enough. But, in case you need another one. ;-)
>=20
> a) v6.11-rc1 + KASAN
>=20
> The result is different from yours, so I ran two tests (make sure the
> soft lockup warning was triggered).
>=20
> Test #1: waittime-max =3D 5.4ms
> <snip>
> ...
> class name    con-bounces    contentions   waittime-min   waittime-max
> waittime-total   waittime-avg    acq-bounces   acquisitions
> holdtime-min   holdtime-max holdtime-total   holdtime-avg
> ...
> tasklist_lock-W:        118762         120090           0.44
> 5443.22    24807413.37         206.57         429757         569051
>        2.27        3222.00    69914505.87         122.86
> tasklist_lock-R:        108262         108300           0.41
> 5381.34    23613372.10         218.04         489132         541541
>        0.20        5543.40    10095470.68          18.64
>     ---------------
>     tasklist_lock          44594          [<0000000099d3ea35>]
> exit_notify+0x82/0x900
>     tasklist_lock          32041          [<0000000058f753d8>]
> release_task+0x104/0x3f0
>     tasklist_lock          99240          [<000000008524ff80>]
> __do_wait+0xd8/0x710
>     tasklist_lock          43435          [<00000000f6e82dcf>]
> copy_process+0x2a46/0x50f0
>     ---------------
>     tasklist_lock          98334          [<0000000099d3ea35>]
> exit_notify+0x82/0x900
>     tasklist_lock          82649          [<0000000058f753d8>]
> release_task+0x104/0x3f0
>     tasklist_lock              2          [<00000000da5a7972>]
> mm_update_next_owner+0xc0/0x430
>     tasklist_lock          26708          [<00000000f6e82dcf>]
> copy_process+0x2a46/0x50f0
> ...
> <snip>
>=20
> Test #2:waittime-max =3D 5.7ms
> <snip>
> ...
> class name    con-bounces    contentions   waittime-min   waittime-max
> waittime-total   waittime-avg    acq-bounces   acquisitions
> holdtime-min   holdtime-max holdtime-total   holdtime-avg
> ...
> tasklist_lock-W:        121742         123167           0.43
> 5713.02    25252257.61         205.02         432111         569762
>        2.25        3083.08    70711022.74         124.11
> tasklist_lock-R:        111479         111523           0.39
> 5050.50    24557264.88         220.20         491404         542221
>        0.20        5611.81    10007782.09          18.46
>     ---------------
>     tasklist_lock         102317          [<000000008524ff80>]
> __do_wait+0xd8/0x710
>     tasklist_lock          44606          [<00000000f6e82dcf>]
> copy_process+0x2a46/0x50f0
>     tasklist_lock          45584          [<0000000099d3ea35>]
> exit_notify+0x82/0x900
>     tasklist_lock          32969          [<0000000058f753d8>]
> release_task+0x104/0x3f0
>     ---------------
>     tasklist_lock         100498          [<0000000099d3ea35>]
> exit_notify+0x82/0x900
>     tasklist_lock          27401          [<00000000f6e82dcf>]
> copy_process+0x2a46/0x50f0
>     tasklist_lock          85473          [<0000000058f753d8>]
> release_task+0x104/0x3f0
>     tasklist_lock            650          [<000000004d0b9f6b>]
> tty_open_proc_set_tty+0x23/0x210
> ...
> <snip>
>=20
>=20
> b) v6.11-rc1 + KASAN + patch: waittime-max =3D 5.7ms
> <snip>
> ...
> class name    con-bounces    contentions   waittime-min   waittime-max
> waittime-total   waittime-avg    acq-bounces   acquisitions
> holdtime-min   holdtime-max holdtime-total   holdtime-avg
> ...
> tasklist_lock-W:        108876         110087           0.33
> 5688.64    18622460.43         169.16         426740         568715
>        1.94        2930.76    62560515.48         110.00
> tasklist_lock-R:         99864          99909           0.43
> 5868.69    17849478.20         178.66         487654         541328
>        0.20        5709.98     9207504.90          17.01
>     ---------------
>     tasklist_lock          91655          [<00000000a622e532>]
> __do_wait+0xd8/0x710
>     tasklist_lock          41100          [<00000000ccf53925>]
> exit_notify+0x82/0x900
>     tasklist_lock           8254          [<00000000093ccded>]
> tty_open_proc_set_tty+0x23/0x210
>     tasklist_lock          39542          [<00000000a0e6bf4d>]
> copy_process+0x2a46/0x50f0
>     ---------------
>     tasklist_lock          90525          [<00000000ccf53925>]
> exit_notify+0x82/0x900
>     tasklist_lock          76934          [<00000000cb7ca00c>]
> release_task+0x104/0x3f0
>     tasklist_lock          23723          [<00000000a0e6bf4d>]
> copy_process+0x2a46/0x50f0
>     tasklist_lock          18223          [<00000000a622e532>]
> __do_wait+0xd8/0x710
> ...
> <snip>
>
Thank you for posting this! So tasklist_lock is not a problem.
I assume you have a full output of lock_stat. Could you please
paste it for v6.11-rc1 + KASAN?

Thank you!

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZqkX3mYBPuUf0Gi5%40pc636.
