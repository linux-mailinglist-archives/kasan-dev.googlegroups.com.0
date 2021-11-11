Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBEHUWOGAMGQER7SP5JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AAEC44D591
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 12:10:09 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id bp10-20020a056512158a00b0040376f60e35sf2568988lfb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 03:10:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636629009; cv=pass;
        d=google.com; s=arc-20160816;
        b=nw9aRf2kRjqLm6F+HV3+ihveTY2lRTQJRXhsCy0eQWd5IOJNReWKCdPkksStV6iFD1
         5J0uM8JejGumoDptnig2bWD4G6XpC1oB2CrICloJ350KaAqKado3c1bgA4QSioM1RPb6
         KLYA1ap1qcP2X5ZdCrgwjguCTHBQwD3pmuWniU5l8xAUEnBIHZzdLH5Nl4tF0lSH9M4f
         7aCjxQe2Hw0K8E58w6E5JkVLM+oBQIlYG7rTOxZSaArTpxB3P6ADUC9E1NfbfCi0eOVC
         3crrUUMkh169kzoiMflt6Tj/x3mxEBGpvQkyVK6J4oXtNBmKRiec3RxPgeFEsdjOQfzH
         H0DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=bl2H6TKVhve6PdfQ5XPoVivaAv/C5+IJlme+zn8Bi70=;
        b=n/Gm185KFBE8aKYqMzp5yezuj11nNkRtXgUfS+MDepTXkvY7oyMSe2JzYSn7PizzqV
         leOHKSA5/QPYM/6WRqr23spF/WS4n3bcA8RUXHVtn1DospBVVdn/tqxKbm0Ef5+vhKW3
         NRJh3lFYMqSeC/1XTu7yFZ9WVDmnP6m9GTz/QU7xd5jToQWzaxGolQDDDam6FIakxSS3
         8CK2HVa6umO94gF7511IbTlPP7/uwgqJR1mXiHWn5kVT59jiCqy7Vq0g1FhtM1agMUaw
         PK89BawqE1J0atmQ0X9oBpTdvCVS3AEQay2r9+P6ynV5q94xHgTQaCrd8c5bkPmKHoBc
         chkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="UTUxLOk/";
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bl2H6TKVhve6PdfQ5XPoVivaAv/C5+IJlme+zn8Bi70=;
        b=Znj5SVfHN5l7mD11lz/o6+/2nUgY/ocES2OBWuiNtIz9doewAqIR+NX3XjjRyrB59d
         OHTe9ACMvVZiC2ikDVDoxJNSWlFdR2Lz1Hyk5crIH06fdm30NVVGhQDJ1RxWDmuOexU5
         21FPoFbXuW5dXV8Kjz/QVnKTHbdQqjOapEqUzUNHy0AiSpu6Z4tZgvXGOHnULoDKktqV
         h7ZLduhKPrggub8jR3a5F5PCZeFQiJncqmJJBNtr5CbiEADBF4cNPyZJZGgYCehmecSt
         +o32pVTucnLuFqtWwZUupJO/sGffB8xum6vNPgKJvNBtBkFwgLuRdBggEYY7+SgEJYwS
         IONw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bl2H6TKVhve6PdfQ5XPoVivaAv/C5+IJlme+zn8Bi70=;
        b=EGYsndNs0/7pcQUlErotKYJzrBJ6tIbgThwKHO7Bxl7bNn/F+gARDZ/5jocJHGanvl
         REWrvMVVak90mL/RSDRF4BZ9SEK55rqt2RhzZFhsVudIvX8BE+fCI+sLa1F42UIlql9Y
         J3jdqCUaVBoyPU1dG9JoY42dbLiOw8Ymv/iacrLq4LsRkNpePHh3SUtWYiddre2RqjTo
         FIq/+0adIr+vGRWypczDZzICN4bTMZMOUWltaSuwoX1jvGmnLcFWpblmc9J/Q/KsmwVO
         3DWFIW7SgUNfi+ahk5uTzb1O574rI6+lxT82Gqijr3rW3NU9tzCAxPb6aCkEKDxyMOT3
         I/Vw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53003hFLWxOBkI6sGoRql2AlMR96X4PxkXxkpANvvGt5Q/3dI3Er
	J8KtqN31Dp0M/RULOxlyat0=
X-Google-Smtp-Source: ABdhPJybUShsvYTxQ8EsgWLOsxMedjfxK163r4ubOYTF/pb9qmOmPUH3p2LYFQBZ6aZmg4OtGkHdcQ==
X-Received: by 2002:ac2:5d46:: with SMTP id w6mr5587565lfd.15.1636629009122;
        Thu, 11 Nov 2021 03:10:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1251:: with SMTP id h17ls500923ljh.6.gmail; Thu, 11
 Nov 2021 03:10:08 -0800 (PST)
X-Received: by 2002:a2e:9915:: with SMTP id v21mr6389166lji.155.1636629008161;
        Thu, 11 Nov 2021 03:10:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636629008; cv=none;
        d=google.com; s=arc-20160816;
        b=wQ9cM2ZT5G2RfBgLip+krDwekca5ecGQY5Ag7waqbLqNd7kjgpH/S9R+EHu0s58pKJ
         oSYFa2/BDqR/lTqStwWS6FxYUKvJhINOlki3YcuypsxSbry3UMomPAFnI1jLF9J4Ovt7
         J282Fq93VOOEICm/q/cz8ay2wIZpp1muphJq0bnLPR6A1W/1Sm9fuLOa6HJy3i+9gEVJ
         QO0jwd0ygsvvNFJXu/+ZiAS1K1mllNJuxCCaTDzWlBH92T0H2rHqEkih/DssvXv3mUfa
         vNp3ITmIRUjkXxBeZ9bioqcPCRQriv02T4UxPOLhyR9n3m+gJZqB+UBCxdsVMlUczVMK
         oNoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Fcmt+X/PRmd5h9DBEzHLOz+jdk7EZdGIW7HhqVwWPpA=;
        b=DQOPHMcKgGGwgQRPFwWVuo5JbjYepS7FywCEoJsCzALZ42BgUg71u8FcTitAEl9tmw
         VlucEFrrpf/hFdrZrKtx903idMmz/w9TnxlMotTGX0Ecamo+qeTJg+VyGRDUovzfHaoI
         DeXXjsskVgRfKqMq2mHq+/Db8ESoUfyksn4ZqMGMs7Yn1GWePBWgBLzR9GO++KcK74dz
         FWm6bVDdEY3e0Hc6gpUoNETsdqJr/QAZ1a9zulC8Xsi+zvorzUBYBtOboEZzBe68g3sW
         qKfkDSh4WfP7Bg9Jsu5tRUwi5JPJTmFLhQC/eU7hsjAzUcabr5ztkmnW8gU/E2KXsBms
         iJ0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="UTUxLOk/";
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id c12si204892ljf.4.2021.11.11.03.10.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 03:10:08 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1MTzf6-1nByG23evC-00R0Xc; Thu, 11
 Nov 2021 12:10:00 +0100
Message-ID: <85ac7c9ccb578155738f2dfdfb74904e677f0141.camel@gmx.de>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
From: Mike Galbraith <efault@gmx.de>
To: Valentin Schneider <valentin.schneider@arm.com>, Marco Elver
	 <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker
 <frederic@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman
 <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
 Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>,
 Masahiro Yamada <masahiroy@kernel.org>,  Michal Marek
 <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Date: Thu, 11 Nov 2021 12:09:58 +0100
In-Reply-To: <8735o3rmej.mognet@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
	 <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
	 <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
	 <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
	 <CANpmjNPeRwupeg=S8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg@mail.gmail.com>
	 <26fd47db11763a9c79662a66eed2dbdbcbedaa8a.camel@gmx.de>
	 <8735o3rmej.mognet@arm.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:b6XWn7xnRrqcRL+59pdpMav+X0ElAqBwSTXFfB30ZrRhE9+Q/tG
 CnbC0FkUyt1tYIRBSNU00o5E7fcsZssc2k3TxttlXIFQhvAM3fvI1lrqbzAKCMOOwI9Q8fw
 kPr6lCNsVKp/0xk3UQQH3k9wNNFvmPeRiyyvNvKBLQQPCSM1RnjJ1f8gd1mgJhSxluULckZ
 +u6IUecArxEcMKflkVYQg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:kKs/s/Utpbw=:rs2TwhUKxUtsfSh7oaDZOd
 kWP0wsK+RiTr3S3cI89LbH37yGehAJDxd+UmrxX7F2Dr7zWNOJJ/flI6MDo79C61PdDatSrkV
 BKCJsHAikUNHd0PJF+FM98W6ZWv4hXSnhYme0WolG/bzZDz/cZ8VI45UtAYhrzu380Uf8pqN+
 FqALEu9owqsnWXbZ1Y7ArYTShNwCc5bsTbxNhm46NSd0E019pZBssjrA64MXeSyUWaGVX4vP2
 KITWr8s6Kv6lXhEpjgNmwGUiSYis3+5DD6KDtbrcOYcsbR8Gr27XDFOKyaO17MxlInwT0C0l1
 6rmWymDW2wHfE/n+Z2+OKc9rbiXx2Y+2mjg/mTd7LrruDOLc/Yzd/DxACcaAGq84sMdpUZk6H
 EyXFXJyaHl/OjyfKJREMhVgUI1xjOj+8tYKhu1ILIJPNwCc7XpM87t9JibebEgQLcs5TN/pso
 GIW6KPxMjlltmLjGagm8mYz72DOaE0UYUzmBo9gD/PntpGyBRzf6li84fjHbaAXH0FmAcj85k
 +4LYiTaLgfKpCEkzRh5vfks5CY8oKAGLZogjk0JzcwWpIhtqbT8tNlgYR3JSqgVXcpGdw2l04
 EZrRU2b1/U1X7hT5ZsvZHE8ZKa9yxmHVYgvhAXWzzgVzxTWYwq3CabjjQqDfCNVu8E/KQdWix
 4b3WPH0vIMXYSRVuVAIZ0tl3Aj1H06dUL555NbHH9FBZuRyd7cVRl9BqTEnhyyqUJtN2Gkwot
 Lt9H1u+f2hBQH1ZuFK0FJj2hnu8y+HFcZH4WTSGX4aljbJvIzbyU8qIckDfTo20PMnmsIqG6b
 vzhDSbHEz0sQIbjqHTpbyVmFw3/MkoLLB4DTf6OcFhdLFzISbnLhHe/vI6QJnTfSaoQVRuMkp
 fIIsik53Mlh+8g0YaGF5NNtZBgyAKiUr6LoiPgFK3/UyovlleIrFcBF/XnLdx4pyVt/PzuTPW
 R7cLhx/3xx5AAeJOZ5+T7cDQjG4hQOv1aopgPGhydICpoFVSsOEu1LsUAYLGjZE8muXa5GgTo
 2l1d9OhK9jOO0v8/R2t7flnoK6XK1XJgh0y6/F0NtUX4UYYBcWPSuK8SqIRyzOo96TOwuMmHy
 jlsP5A/KKvnNWI=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b="UTUxLOk/";       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Thu, 2021-11-11 at 10:56 +0000, Valentin Schneider wrote:
> On 11/11/21 11:32, Mike Galbraith wrote:
> > On Thu, 2021-11-11 at 10:36 +0100, Marco Elver wrote:
> > > I guess the question is if is_preempt_full() should be true also if
> > > is_preempt_rt() is true?
> >
> > That's what CONFIG_PREEMPTION is.=C2=A0 More could follow, but it was a=
dded
> > to allow multiple models to say "preemptible".
> >
>
> That's what I was gonna say, but you can have CONFIG_PREEMPTION while bei=
ng
> is_preempt_none() due to PREEMPT_DYNAMIC...

Ah, right.. this is gonna take some getting used to.

	-Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/85ac7c9ccb578155738f2dfdfb74904e677f0141.camel%40gmx.de.
