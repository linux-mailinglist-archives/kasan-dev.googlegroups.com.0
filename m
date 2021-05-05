Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGFLZOCAMGQET2E4SSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 132BD37437B
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:27:53 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id l10-20020a056830054ab0290241bf5f8c25sf1581911otb.11
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:27:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235672; cv=pass;
        d=google.com; s=arc-20160816;
        b=W8ZkZCwx4gi/v+IDlgxKPzqBOoexsxKjORyAkbJ2Fos+mbIwWGRktRSSjUJ9rzStaF
         RIGZZzXNIFntKtWQA6XXT88CsyiRdPjuCWC+fIr1LM8Kcnho+cwVdokkQYAOvwFeT5ZY
         SMAI8I6HqWMbR/sV/9kh1nuCzUEh5LhWGszhXL43K2+fsosiOLRPqfTTwjQ0QLCOdYDO
         5nEPX2KaSIhy94dbVS+HgCOFfoW1Pc/XfIC6qdK7WIQL/UDp/N9Rc6pfLdtSMZ6WacR1
         v8A+9ucuxDXxgYSryq64Yl3OVxooURrisp1DZdiv+cOVozIzxoBeP6GMSz9azs7ezgA5
         Ja8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OA+QIzvoOBy2aGeyJeQ1FjQBLdFsgpkvuYBQ/uhW4U8=;
        b=nvMBCDJSliJWFr++1mY3qiW00fqk8pRTt7xf12Wo2rsJbIaIqNKfE38fqGHSptQYLp
         sAwM9Gofo8pObGz6DlnrFJE3YoxOy9suitgVucPUZ05hFprj9m5WDuyhZiTQEo7s4V7W
         EqC8QCXkcqD7320b5OSgE9O36RFSFbbnzDMUk7mXiA/6+mLeJuRwmEY8ExNPZsPpreWO
         h6gUIjenLMQ/8/AB3+9Ghd1m4/6FduIh91VVzNggqzm42s3SdW8O80epJY+G2zSzMaN8
         tUlLWG2oYnpY0Zqyga/v7H2CTnby5z3/8ZMT3gDorAcaGlMPvqELps8RfNypO+7pV8fX
         3knw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vI0evSyV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OA+QIzvoOBy2aGeyJeQ1FjQBLdFsgpkvuYBQ/uhW4U8=;
        b=pn4d8fE6p5fXWePVxLxDD1/PCcFULgumo2GzsgqaSv2KD7SHm754tcVy//A+r/qKox
         NFzvGWJdHOl06PUkBG9BoInVZLQvspSlHxrT6+ia8QrzhqjyuZ+32IWDYsV1Kdx0MU+t
         1H0/daYoYwZmxw88Cc0wcm5+THkdl/n+FmO0aM5Y/ABGFBK1/+oPQAGm9X11RTgIgZzn
         rHm831KIZkeOhgiejLAPg2z51cc5PSl3ES5gddPmcsW3yDbpFFuFyp5YCP2gWsCMxsTp
         5mrEqtsQno0q8eiuL2BT+1JMurTEmXVNnWVDf7l8a1Q1x0q9BkxECdHy7vuMbE0ort28
         Prbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OA+QIzvoOBy2aGeyJeQ1FjQBLdFsgpkvuYBQ/uhW4U8=;
        b=WLuhqSnQEoiLBRz69sPSxmd5N7uEqZAFY4mlxcz6kAawAnfb3/CpF+hEXTwelJU6Bo
         uo7xasKm9cJgzsYXz6fndEJiYz1bovZo2g52ygNZVuquGfkIjuY+c2e7QmARz1kzepod
         +mHbFykY5nMDFdNxc5WeXm5gHAvaj/kj3yanAi5M45sImdIebSZNee4E3BCgBE5CnP1w
         TmCq2IWm55uQdFaYwmurSxoYmAMJdj3gYVsOz4g/oWrLbymeMWO6XcsSOgweC+g1oQpM
         dAQ/Zp6ZRO+y4u+6viMtqauFolb51sr0rltwDIrNm34LiMZquv3sKlbu/LauYti8t9Ai
         +BCA==
X-Gm-Message-State: AOAM532zoP/v9fnW1jW+D+In6j/rpLrKfKlAlk2m9fWCvcubghET3bnf
	QAEjHoHfMRF9LNVeFLxjJyg=
X-Google-Smtp-Source: ABdhPJy2FtXprQ770Y/SZjctAB4Tj2r4npgW8Is1dDNbARDp5mVYCcZ/xOD47ri09iug4kAFlvHGuw==
X-Received: by 2002:a05:6808:1405:: with SMTP id w5mr30839oiv.48.1620235672074;
        Wed, 05 May 2021 10:27:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1e0a:: with SMTP id m10ls6084375oic.7.gmail; Wed, 05 May
 2021 10:27:51 -0700 (PDT)
X-Received: by 2002:aca:4bc2:: with SMTP id y185mr7478469oia.64.1620235671714;
        Wed, 05 May 2021 10:27:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235671; cv=none;
        d=google.com; s=arc-20160816;
        b=rkmsyvJURzaHAUt9F/X3LzU/+JytZ3gdu+10YiOSOTKl5T5VL4i6tA0pwDNwGWNd55
         vKhyeNaXFk6FNN3WH/TxS5Qjy/OmLUHmJKO65qrDkKyyiJD2FdUr3v3q9bBffcQDv/Aj
         OJjo5KzWP3HE7fstyKdjVRiqJLEguHWj8pRve1MxdUmbJhv0/4HziK5a9pF+buxq1dtC
         RjC6/ooMg9VA+C3uz2IsrQcdfCeyAqPldchikMDmJtDjXzlOYNEE/rlaxALQd28CTU9a
         ghDjqoza44SMmnYvp3rhwr1UPgXcug4QZvVF8AcIY8WiEJOcF+7x7ldkZtXFgJDXuw37
         xFGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EpXkesvqHOL8k54CBCo40z1c8NG5SDEJNQ8hz6LZPW8=;
        b=m/ILWbX2i8lYP2fDTtgLLXc6nlbecYbETSmjaEmSqnXJVMXEB9nuQt34CUwwfOGSDf
         nugspf6GZdu4SGpghW6uj4ENtfVgX+NDnDCzAqYnkekmDXkIPYMjmibVstGkjkGHxhpk
         GfFFXNMIKP/DbCaK6iW9W8F6qm+e1btV2ti4bHzzagGwvnIZBSC/yWOaxueqavXbcsYZ
         2IPV9Om8OjrYbKyPQ2YN+w6ZBcW0fgogw0t0TE+8OFWm2ZTlt001r9D4RfIDz2nakPqM
         Bb3Zndsz3UUcZ6zmnOdymEbMRjeKq2RDlpCiWw5NCC1/wFRbCZ3pAMH6N05JQJeN31mO
         KdXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vI0evSyV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id w4si362863oiv.4.2021.05.05.10.27.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:27:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id b5-20020a9d5d050000b02902a5883b0f4bso2415836oti.2
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:27:51 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr25559833otn.233.1620235671263;
 Wed, 05 May 2021 10:27:51 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-12-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-12-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:27:00 +0200
Message-ID: <CANpmjNPcYS9F+mgFP_DnO5c7kmMs28cdMBWN+ZxE7YNe_oK=_w@mail.gmail.com>
Subject: Re: [PATCH v3 12/12] signalfd: Remove SIL_FAULT_PERF_EVENT fields
 from signalfd_siginfo
To: "Eric W. Beiderman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vI0evSyV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> With the addition of ssi_perf_data and ssi_perf_type struct signalfd_siginfo
> is dangerously close to running out of space.  All that remains is just
> enough space for two additional 64bit fields.  A practice of adding all
> possible siginfo_t fields into struct singalfd_siginfo can not be supported
> as adding the missing fields ssi_lower, ssi_upper, and ssi_pkey would
> require two 64bit fields and one 32bit fields.  In practice the fields
> ssi_perf_data and ssi_perf_type can never be used by signalfd as the signal
> that generates them always delivers them synchronously to the thread that
> triggers them.
>
> Therefore until someone actually needs the fields ssi_perf_data and
> ssi_perf_type in signalfd_siginfo remove them.  This leaves a bit more room
> for future expansion.
>
> v1: https://lkml.kernel.org/r/20210503203814.25487-12-ebiederm@xmission.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  fs/signalfd.c                 | 16 ++++++----------
>  include/uapi/linux/signalfd.h |  4 +---
>  2 files changed, 7 insertions(+), 13 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 335ad39f3900..040e1cf90528 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -114,12 +114,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 break;
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> +       case SIL_FAULT_PERF_EVENT:
>                 /*
> -                * Fall through to the SIL_FAULT case.  Both SIL_FAULT_BNDERR
> -                * and SIL_FAULT_PKUERR are only generated by faults that
> -                * deliver them synchronously to userspace.  In case someone
> -                * injects one of these signals and signalfd catches it treat
> -                * it as SIL_FAULT.
> +                * Fall through to the SIL_FAULT case.  SIL_FAULT_BNDERR,
> +                * SIL_FAULT_PKUERR, and SIL_FAULT_PERF_EVENT are only
> +                * generated by faults that deliver them synchronously to
> +                * userspace.  In case someone injects one of these signals
> +                * and signalfd catches it treat it as SIL_FAULT.
>                  */
>         case SIL_FAULT:
>                 new.ssi_addr = (long) kinfo->si_addr;
> @@ -132,11 +133,6 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>                 break;
> -       case SIL_FAULT_PERF_EVENT:
> -               new.ssi_addr = (long) kinfo->si_addr;
> -               new.ssi_perf_type = kinfo->si_perf_type;
> -               new.ssi_perf_data = kinfo->si_perf_data;
> -               break;
>         case SIL_CHLD:
>                 new.ssi_pid    = kinfo->si_pid;
>                 new.ssi_uid    = kinfo->si_uid;
> diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
> index e78dddf433fc..83429a05b698 100644
> --- a/include/uapi/linux/signalfd.h
> +++ b/include/uapi/linux/signalfd.h
> @@ -39,8 +39,6 @@ struct signalfd_siginfo {
>         __s32 ssi_syscall;
>         __u64 ssi_call_addr;
>         __u32 ssi_arch;
> -       __u32 ssi_perf_type;
> -       __u64 ssi_perf_data;
>
>         /*
>          * Pad strcture to 128 bytes. Remember to update the
> @@ -51,7 +49,7 @@ struct signalfd_siginfo {
>          * comes out of a read(2) and we really don't want to have
>          * a compat on read(2).
>          */
> -       __u8 __pad[16];
> +       __u8 __pad[28];
>  };
>
>
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPcYS9F%2BmgFP_DnO5c7kmMs28cdMBWN%2BZxE7YNe_oK%3D_w%40mail.gmail.com.
