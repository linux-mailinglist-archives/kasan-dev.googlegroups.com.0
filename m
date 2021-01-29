Return-Path: <kasan-dev+bncBCMIZB7QWENRBZ4CZ6AAMGQESWREKEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 29C253086C9
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:03:53 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id h25sf6152921ioh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 00:03:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611907432; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZPY7rDbrF0whxeZVsbUAjvchvYlWDY4ZXASNM++YLrnXBRAPoY/FkTRFpaU16JADx
         qdIGQHoyS7W19ohzZomYisndXqvRxqcitX+fqNXVcbtOevVJh+nYht4Z0V6iXNh2NX4w
         XmCfds7UMFW0k4kePG6ejUSXqDtRdRiE6573BfrUfatknWWKxp6fc9+i8/JLqOwclpwq
         94xEhByIFci/25NfVi24y2BAhISY44PTf68CmDe5gxm3R9iVyGWdNKeq25H45D7V5f24
         nL6BTpeJqVYYiVSD1xvUH+czMXtCpNo2NUYQ5kU/w0Z73doXrBGY5lrtr2GVnlhLMMps
         +Hdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=65Jy6HHoxbxy6OXvJ0BJIWuhJhgbEXwr9Y0qYEI5y4g=;
        b=KOQx8Dntv39WQgMjpXa3boxJVMRmzOQKSQWR7mtdq1C/xXOdB3gzLXv2XBGVaymJio
         IHpUVBIdaIbJ7jRV9R2cl7MGbBZIgV7VGWrDfMRtg6dfQTyiIys86WsOpw9MwsPb3NrE
         t0SZiR0hWuorGUukZIDvJzRIDE8sRQnczxBbCaT4EO/7jtGLaB+Us2rhHCPVqDMRVwCy
         axvZY+McIdygMO/uRF3lvPcPsEEgdnjsRm9kxfVEB8fwIJPcvVzkM0Y/iQ1iebpIbxaK
         A8cbe+dGXWdiBYsiw/5ylof8ajP3+k/xL6p2/Vqq8bGJORGAlKjVsMnCcfnNFg0hKTLG
         HvSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sAIgwEce;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=65Jy6HHoxbxy6OXvJ0BJIWuhJhgbEXwr9Y0qYEI5y4g=;
        b=tKFAr/f3sBpggWYs6IrXhdZRUSRUrvay1yyZx001j7IjUIL2A3xCY9/Nfo95s87XQ0
         GLxmQ7nd6r2+wC9XeUfz7+Qk/y4V3NHcFfFKE9abuAL2dJwKcbwakKCH5JxgV8AUH0Y3
         3iyvDQtuI0P9WhA+b0W2Hmd1ihsk3u/6L9IrXFTTpiYa1QU6Au4lp2d83XdF2cYXc/VI
         8Qeal7ytDZyBsd3ITwz521G+CCNFK2jHBbjrVJSVcfVZ4H+E2DCUgy3mq9jHD/iIGCGm
         qTaQTjW2v/LueOTBL5gnfKhqrMX+vlzPqHbv1rmbyWQfJoiz8Vwwr4sHQu1X/Y8k+IRL
         Sy8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=65Jy6HHoxbxy6OXvJ0BJIWuhJhgbEXwr9Y0qYEI5y4g=;
        b=A39Tl/+iVH7toeeuZvdwdyKhFhEfV0VVvEaYCmZymcLvUvzK9cUvxKAGQkBPCGsuT/
         TaKSjim2w7nZDjfrGnj9KE/lMfbDoc8Sj0aJDljlblzI69XT3hK8fhXUTd7C9/HG61Qb
         saDLibEe8ab0gruXOsZXfs8hacQoYxGCPcwbUhbTA5GvO876B434Y/fAkW0u5BgwpRnh
         FFoWHwLa+YCkOnmmhcgn2Rxk+edx7AiBQFwF64DjKKrS8q2SlpTJRBkPkeRysAgz+6g+
         dxTM+maBOgFRZ59fQaBFeAGjc7j+eWlDEi5q5HNfd1E4+I56VpU0Y8sIHa2UQsH50mz5
         +h5w==
X-Gm-Message-State: AOAM533vEMbrUVXACrxD66HTdtxvFXiC3eqZpsCMgvlfgS4bufmgQ4wm
	B67hBRN6Jw2IlZtLSCDXbCg=
X-Google-Smtp-Source: ABdhPJx/OqK7KOTQDAljO045BVGUPAYcMYJHTirAai7/PIUijNf8S1hGcJ3pcWX0oDARMPcqqxE0Aw==
X-Received: by 2002:a02:3843:: with SMTP id v3mr2888782jae.70.1611907431964;
        Fri, 29 Jan 2021 00:03:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f0f:: with SMTP id a15ls2030760ild.8.gmail; Fri, 29 Jan
 2021 00:03:51 -0800 (PST)
X-Received: by 2002:a92:2903:: with SMTP id l3mr2357539ilg.242.1611907431553;
        Fri, 29 Jan 2021 00:03:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611907431; cv=none;
        d=google.com; s=arc-20160816;
        b=pc+RVIaA+eoolrW2oHthqTNP8zTlRq2+ZTJlhiF6h2mICsiF0jys/UapzorJo048OO
         PX7RUc9gb9eqLrm1rFHzUvbEdLEDF34hK3VEQ3qMdaRN5oyDH2KjjSZBnWwCIbMIWYQd
         Sw/BdMH7Vg+McdQ89Nrw3CFrx/BgaM8UHKjpY6x+evsAOCyqJE1DsdDfRaiipYClQajL
         1WDsiM+BTH1CzjMNZomK6uP34ZLL5ZHboBtHpeNYLORboc+vvM13sB/ENPV2xeY/dZpx
         h9rLRxMpEI1I0ybg37jfZn+x8hbsNU9ZvyLGSallZG6EkJ5GextLV0jqOzbMDTLBPlun
         sMvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ypys3vYFG0bK/g/umBtdUdDK3RUurq30Hl1DKM2cIWI=;
        b=Y+N9po/U6HfFrR+klMiHW/2nwwQgUpZoGsddRg4AK2R67R8XJTH+FQiNmM4Dc69FJi
         jf67P2LtYRUqR3Qa9RM+qK7R+0cu4T1bi6OXUY80myLfiiJwk+2UBHhzGxrg5lh/g9zH
         VMN/YLrQBhSvCemdFvrncok5Dlod9kP8/yhusy4UsHB1uym8YuDKKmC1oQXXxrmywIvL
         Cq72mKrhT9i4ENZitOWGdUd531ypGRFS0gqlmvYH7CGn7vea7A5YyLQDs30bPD++G5qg
         I26UEOE2HY1G7s6wQ3a5q+qllx4quYSbJ6o9gAKM6cotqboB7QDvpF9pcZRoyzLK+H0R
         rb1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sAIgwEce;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id o7si41527ilt.4.2021.01.29.00.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 00:03:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id a19so7984142qka.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 00:03:51 -0800 (PST)
X-Received: by 2002:a05:620a:918:: with SMTP id v24mr3014741qkv.350.1611907430759;
 Fri, 29 Jan 2021 00:03:50 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
 <20210128232821.GW2743@paulmck-ThinkPad-P72> <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
In-Reply-To: <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 09:03:39 +0100
Message-ID: <CACT4Y+YFfej26JkuH1szEUKKvEP-TaD+rugdTNfsw-bALzSMZA@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sAIgwEce;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Jan 29, 2021 at 1:07 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Thank you for your reply, Paul.
>
> Sorry I did not state my question clearly, my question is now I want to g=
et the call stack myself, not from syzkaller report. For example I write th=
e code in linux kernel some point, dump_stack(), then I can get the call st=
ack when execution, and later I can translate the symbol to get the file:li=
ne.
>
> But the point is dump_stack() function in Linux Kernel does not contain t=
he inline function calls as shown below, if I want to implement display cal=
l stack myself, do you have any idea? I think I can modify dump_stack(), bu=
t seems I cannot figure out where the address of inline function is, accord=
ing to the source code of dump_stack() in Linux Kernel, it only displays th=
e address of the function call within 'kernel_text_address', or maybe the i=
nline function calls have  not even been recorded. Or maybe I am not on the=
 right track.
> I also try to compile with -fno-inline, but the kernel cannot be compiled=
 successfully in this way.
>
> Syzkaller report:
>
> dont_mount include/linux/dcache.h:355 [inline]
>
>  vfs_unlink+0x269/0x3b0 fs/namei.c:3837
>
>  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
>
>  __do_sys_unlink fs/namei.c:3945 [inline]
>
>  __se_sys_unlink fs/namei.c:3943 [inline]
>
>  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
>
>  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
>
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
>
> dump_stack result, the inline function calls are missing.
>
> vfs_unlink+0x269/0x3b0 fs/namei.c:3837
>
>  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
>
>   __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
>
>  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
>
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9

Inlining info is provided by addr2line with -i flag.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYFfej26JkuH1szEUKKvEP-TaD%2BrugdTNfsw-bALzSMZA%40mail.gm=
ail.com.
