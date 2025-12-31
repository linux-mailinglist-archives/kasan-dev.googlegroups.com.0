Return-Path: <kasan-dev+bncBCDKVZVOUELBBDW42LFAMGQEYV743OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id B9830CEB452
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 06:01:05 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-8b8738fb141sf2768773985a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 21:01:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767157264; cv=pass;
        d=google.com; s=arc-20240605;
        b=P3TO6pxwGkj7a5Y++P72qwrLcpd/JOEB2RPFt63/gAEY/JBEF7Lnc+NNULpxs8Nxxi
         FSjii2wOikGZ+KO52Fg2l15nRidonF0lXr3tssY/ah03lbSFnUCWQzdhLXZtnaGzLn5U
         r8+parZo2XD3UACERABFHIOW6ptwv/5KIhSOXQAeIrSKUbExq8Ada6a1/70FTR7GjSZD
         8aEHEHnWcbjYvdFi71pAXW01tiA6AOJQlJUrej3n2+QERdOwwQV5qiFCT5YGE4FuY+f5
         X5JXp2QaKCUvFtJ2Du7AHpIe+P594miTNqAauVUvAHx5fTd9ZHQ78lXyS4WXwICZAwYS
         /0eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=xf5slBE6VMrrARPv7/KRFrHSCZyi0lseFEo09nfxTo8=;
        fh=h8BsOMhBlL9cHfl/g7ubZIS7FT+MiVCJMvvi8mgvWR8=;
        b=LKkN82fDSbsPUbnYPamCDu8U9AGQITd6SfUuA0EbhpHdBIExXBfAmH10P35QH0O3Cm
         CiISrOJl6/s9vFPhts69lnBnTBN/f7vb6AIGdrbV6njxMIDlzo27HcqFihvnAyN3K5mM
         W8BpYpKB9NI3KpeL+uV7dXaL5gboJsy8wZUTZuOPE04gU4RGmGb6hdlpLTHU3MGm0OPv
         RaCe5aiq/NmToJiL9WDnOHQpC6HhaFMm/77cSgfc2t1FAby1x8C6iljzOcVaCacmM66V
         4QMAaSNDjb4vK0ylGHhqsmANT1gx4XELicublvYAVDsTCmzYEhvN82UvgTNr7fTujddC
         /pgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quora.org header.s=google header.b=bqvbSNGB;
       spf=pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=daniel@quora.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767157264; x=1767762064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xf5slBE6VMrrARPv7/KRFrHSCZyi0lseFEo09nfxTo8=;
        b=rBW1vXJaG6OIBNEHCAnvOaiDxsIe1+QTeuW5W8C8IBketvN+K+Qlpymp5YEjU4O5+V
         gitCwKwyLcc5Azk6AWdLcYHj46fELtB3gg3ef7VIC4G9Qw02Yg1FpSngnTtzvg02J5do
         fnwkPtSJuVfUfh1iUlOSMUZPlkVVgITLCavCQm9BkDnfMnQNxtxUkO/t/H9YtU9uJZ0W
         kzsrTmbPW0d4bOrW/PpMZ9j+TDxKvreHoRszXjYM6ZaenlTbxpJnBUFqQzuHepP6NZaq
         t0cG53zDrrYombNH35B8OfXDUibK4FLoO1XxeCAsoY++jylGoie9fcXmbIxhEGhxU33k
         1Dkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767157264; x=1767762064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xf5slBE6VMrrARPv7/KRFrHSCZyi0lseFEo09nfxTo8=;
        b=L9mOEAdCnHHS3FR5oPHZuHiVVGOItC/H1jTGP422mqYmpdfcQAdvJzls/LBJXEtsgB
         disiWugHIDVjYN0VCabdCZQKK9a7WDeAUUpVnwvYwiC+4+Td95zQMTZsJx2a/zZJNiU3
         m8SjA6v9iVAGBnCugNNHW3Vo9a5+9OOavjn4eaesvwdS0R8v3TsEMuWtwceBSp3o3x+w
         IOQRM9OkB9DLcImsDHU8f8MQjdJkNkKbSJqCE9bYvV0fyib9CoSfJa+Bp0KCRjHjjL5J
         tUAymS1xRU9kwyJwlcKFCj7e6KWq0RM69ZkTuLiepUXM44nkEReRi1COGW/cJYyb5qNg
         Ke9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUvlGPixeIo4QjD60A6fJDDbodHvtKg34heXudwLye27OZU3pyjp/TiMcIlD3M+Y2I5yYG1Q==@lfdr.de
X-Gm-Message-State: AOJu0YypLTGSPXWv1QqRQTUeRqEOVI4hR2vHgTwATSg9r5YHbWlCBeI/
	CkZacBI/hd9QZLF5pTdf2wyj3ApfuEuo8ymnA27Gplu9dEIjyrfehP8R
X-Google-Smtp-Source: AGHT+IFBH7FZ3QI0OyNBil6AuYweTKBEZjtvToTDqlz9l4w0I+KHlAsSSTHTMe/3a3yq1JB1FZQnNQ==
X-Received: by 2002:a05:622a:4c11:b0:4f1:af84:f1f8 with SMTP id d75a77b69052e-4f4aacc273bmr585726311cf.12.1767157263156;
        Tue, 30 Dec 2025 21:01:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaa/c5/Z1ly9DZm+MGb8FeCnfDNQwr7mTT0lH7CrD37fg=="
Received: by 2002:a05:622a:14d4:b0:4ee:234a:302a with SMTP id
 d75a77b69052e-4f71c1027e0ls47676051cf.2.-pod-prod-00-us; Tue, 30 Dec 2025
 21:01:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSIr7rMLvy3XZ5fc4CX+Q5IFihaNkas6F0axHWV1uZPpVPUtOel2apKHmbSbQBGS5MLSaaMvDyt8w=@googlegroups.com
X-Received: by 2002:ac8:4912:0:b0:4f4:bce1:31b6 with SMTP id d75a77b69052e-4f4bce13d18mr308872581cf.19.1767157261882;
        Tue, 30 Dec 2025 21:01:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767157261; cv=none;
        d=google.com; s=arc-20240605;
        b=O+r9YBARjeaEsCkY3cZNd1u6y06OvR7EcXh5EIDnZGGa9gEC+/shVwEDsUNmXw9Ybn
         gutiMVq21JlwIsmxVMobrtH7nBgC8jRbPwEOWaLezqn4/8mza3EXL5BqYFvnd4gTV9SA
         pVo9nyukMBbkMa3/tBH2BTY/4iGlOsdE8/HT+57nRkRqxuJJZtg0VJYy1BexMvC26Adb
         mCBy9eXEzz1xjxEfFLGF9gpBG5IKS5Gw8c90rfA/nDH8hdpGOy0erGxeLfkVAcHa/Wi3
         L3pUP6W5tb1EmqyEsRwqORt4lhgGiMCMsEyt+RtipA4fDL1gDlwwrX1I49jUtJHWZuhN
         tw9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vILZq3yFlzvw/Wkw3qG58Pyg/FPe3qSBf5TB1FRbsr8=;
        fh=SbD3khMOlBABq0HC4WWpeaO0uCGtFPjrQ0SIf7UVwMc=;
        b=DQS9u12BVMCBhL4ngQhvJ7pTdCWTdOt43rgYc1ijaLKjcU4n5Dcxgo6Uxy3bcQrEP0
         5Lp6tIamqsEaL7IRlUAN4tMaAfGS3EQ+tuWRC0L4AigUezgcBnLhiRzJ7YzWIPVEUB+l
         nDRnf/pYUz00puGnxRK0SicNHZuWVSSc6OJ8rP0JHghr6KzDzWxekoyXaLiQbizc9Rz6
         BkCPud0gaftmNyMICb2etyz5yU0dQX+tMolc/v1JR2Ahf3GC2LHdr74z18kuU6Q5D+Ih
         T5jZgjP99km4UobRWuWCSM21EU0tbz45wesvIQbYekzk0g4tyJET1+PjyXGUZMJkM3zF
         lcBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quora.org header.s=google header.b=bqvbSNGB;
       spf=pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=daniel@quora.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88d971b6626si17883946d6.5.2025.12.30.21.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 21:01:01 -0800 (PST)
Received-SPF: pass (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-34ccdcbe520so6108630a91.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 21:01:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXsP1BFYjPkg4mdre2gTrNQagS8abYmwGlUQ6ka3KyDyi3cRZUN2euHpYG54LCvOvsxlocme8wa6Uw=@googlegroups.com
X-Gm-Gg: AY/fxX5NG1sVOzbPrMC/yKqTUjmc3FY5gWjwOftHGHnCAXBVfAfkFV+zOetKuSVHwsR
	9WZrMxK9Zruq/LlXUhiyqcZwegumFs6f12N2nVdyTzIPnrEFmb4/qV17zXi99VmoWLhpwTHcQnL
	W9SgjqwghQjHbSdEtUWwpf4AHPsml1twKe/Mg5khfPrpBY+X8+i2KdshM6CoX75kdpAH8/OPf+0
	bg+a9YcUhfDOYmlDsmbcUKvI6wRQo91Ud/OSXRTH5ACPHakcZy1YYnV0o/DTLcQ/PGkCuwRKakJ
	vH2DuTIGqiy4F49vu+l6qXlJhMyu0kGWN6/AKKdgUZrZODs7kqhpY/NPZzIWNN+AlZJsMKUDiFp
	qXfc6ivVT/x10IMgBHPp4QUe5rOURvBxwnu4b8FAPfxf5zsijo8mw5pKJWLBIPRpSBbzcAhOSmm
	3B3R7sC/U/4ivwZrnWBgRUdaoNUZxyHJsuA1Vb1OA4p0oWjAQ=
X-Received: by 2002:a17:90b:4ccd:b0:32e:3592:581a with SMTP id
 98e67ed59e1d1-34e90df6ab4mr31867856a91.17.1767157260914; Tue, 30 Dec 2025
 21:01:00 -0800 (PST)
MIME-Version: 1.0
References: <CAMVG2svM0G-=OZidTONdP6V7AjKiLLLYgwjZZC_fU7_pWa=zXQ@mail.gmail.com>
 <01d84dae-1354-4cd5-97ce-4b64a396316a@suse.com> <642a3e9a-f3f1-4673-8e06-d997b342e96b@suse.com>
 <CAMVG2suYnp-D9EX0dHB5daYOLT++v_kvyY8wV-r6g36T6DZhzg@mail.gmail.com>
 <17bf8f85-9a9c-4d7d-add7-cd92313f73f1@suse.com> <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
In-Reply-To: <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
From: Daniel J Blueman <daniel@quora.org>
Date: Wed, 31 Dec 2025 13:00:49 +0800
X-Gm-Features: AQt7F2qT5oHGObC_DYrjXo69zJNwTh7g0QjrZk2RyITMANLNzXLeFHGvNjhYFew
Message-ID: <CAMVG2subBHEZ4e8vFT7cQM5Ub=WfUmLqAQ4WO1B=Gk2bC3BtdQ@mail.gmail.com>
Subject: Re: Soft tag and inline kasan triggering NULL pointer dereference,
 but not for hard tag and outline mode (was Re: [6.19-rc3] xxhash invalid
 access during BTRFS mount)
To: Qu Wenruo <wqu@suse.com>
Cc: David Sterba <dsterba@suse.com>, Chris Mason <clm@fb.com>, 
	Linux BTRFS <linux-btrfs@vger.kernel.org>, linux-crypto@vger.kernel.org, 
	Linux Kernel <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: daniel@quora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quora.org header.s=google header.b=bqvbSNGB;       spf=pass
 (google.com: domain of daniel@quora.org designates 2607:f8b0:4864:20::102e as
 permitted sender) smtp.mailfrom=daniel@quora.org;       dara=pass header.i=@googlegroups.com
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

On Wed, 31 Dec 2025 at 12:55, Qu Wenruo <wqu@suse.com> wrote:
> =E5=9C=A8 2025/12/31 14:35, Qu Wenruo =E5=86=99=E9=81=93:
> > =E5=9C=A8 2025/12/31 13:59, Daniel J Blueman =E5=86=99=E9=81=93:
> >> On Tue, 30 Dec 2025 at 17:28, Qu Wenruo <wqu@suse.com> wrote:
> >>> =E5=9C=A8 2025/12/30 19:26, Qu Wenruo =E5=86=99=E9=81=93:
> >>>> =E5=9C=A8 2025/12/30 18:02, Daniel J Blueman =E5=86=99=E9=81=93:
> >>>>> When mounting a BTRFS filesystem on 6.19-rc3 on ARM64 using xxhash
> >>>>> checksumming and KASAN, I see invalid access:
> >>>>
> >>>> Mind to share the page size? As aarch64 has 3 different supported pa=
ges
> >>>> size (4K, 16K, 64K).
> >>>>
> >>>> I'll give it a try on that branch. Although on my rc1 based developm=
ent
> >>>> branch it looks OK so far.
> >>>
> >>> Tried both 4K and 64K page size with KASAN enabled, all on 6.19-rc3 t=
ag,
> >>> no reproduce on newly created fs with xxhash.
> >>>
> >>> My environment is aarch64 VM on Orion O6 board.
> >>>
> >>> The xxhash implementation is the same xxhash64-generic:
> >>>
> >>> [   17.035933] BTRFS: device fsid 260364b9-d059-410c-92de-56243c346d6=
d
> >>> devid 1 transid 8 /dev/mapper/test-scratch1 (253:2) scanned by mount
> >>> (629)
> >>> [   17.038033] BTRFS info (device dm-2): first mount of filesystem
> >>> 260364b9-d059-410c-92de-56243c346d6d
> >>> [   17.038645] BTRFS info (device dm-2): using xxhash64
> >>> (xxhash64-generic) checksum algorithm
> >>> [   17.041303] BTRFS info (device dm-2): checking UUID tree
> >>> [   17.041390] BTRFS info (device dm-2): turning on async discard
> >>> [   17.041393] BTRFS info (device dm-2): enabling free space tree
> >>> [   19.032109] BTRFS info (device dm-2): last unmount of filesystem
> >>> 260364b9-d059-410c-92de-56243c346d6d
> >>>
> >>> So there maybe something else involved, either related to the fs or t=
he
> >>> hardware.
> >>
> >> Thanks for checking Wenruo!
> >>
> >> With KASAN_GENERIC or KASAN_HW_TAGS, I don't see "kasan:
> >> KernelAddressSanitizer initialized", so please ensure you are using
> >> KASAN_SW_TAGS, KASAN_OUTLINE and 4KB pages. Full config at
> >> https://gist.github.com/dblueman/cb4113f2cf880520081cf3f7c8dae13f
> >
> > Thanks a lot for the detailed configs.
> >
> > Unfortunately with that KASAN_SW_TAGS and KASAN_INLINE, the kernel can
> > no longer boot, will always crash at boot with the following call trace=
,
> > thus not even able to reach btrfs:
> >
> > [    3.938722]
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [    3.938739] BUG: KASAN: invalid-access in
> > bpf_patch_insn_data+0x178/0x3b0
> [...]
> > Considering this is only showing up in KASAN_SW_TAGS, not HW_TAGS or th=
e
> > default generic mode, I'm wondering if this is a bug in KASAN itself.
> >
> > Adding KASAN people to the thread, meanwhile I'll check more KASAN +
> > hardware combinations including x86_64 (since it's still 4K page size).
>
> I tried the following combinations, with a simple workload of mounting a
> btrfs with xxhash checksum.
>
> According to the original report, the KASAN is triggered as btrfs
> metadata verification time, thus mount option/workload shouldn't cause
> any different, as all metadata will use the same checksum algorithm.
>
> x86_64 + generic + inline:      PASS
> x86_64 + generic + outline:     PASS
[..]
> arm64 + hard tag:               PASS
> arm64 + generic + inline:       PASS
> arm64 + generic + outline:      PASS

Do you see "KernelAddressSanitizer initialized" with KASAN_GENERIC
and/or KASAN_HW_TAGS?

I didn't see it in either case, suggesting it isn't implemented or
supported on my system.

> arm64 + soft tag + inline:      KASAN error at boot
> arm64 + soft tag + outline:     KASAN error at boot

Please retry with CONFIG_BPF unset.

Thanks,
  Dan
--=20
Daniel J Blueman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AMVG2subBHEZ4e8vFT7cQM5Ub%3DWfUmLqAQ4WO1B%3DGk2bC3BtdQ%40mail.gmail.com.
