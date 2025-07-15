Return-Path: <kasan-dev+bncBAABBVWE3DBQMGQEDXJCQHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB0DB056D7
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 11:41:44 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-74ea83a6c1bsf2394239b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 02:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752572503; cv=pass;
        d=google.com; s=arc-20240605;
        b=eiFrZOQtFC64rPqZTplNeeMjl8G8kynb4I8JClgJJN/QbeIJf8OK/Wndb6bFE4JiHY
         i3QgZ/opo9nfRafyiDN3dY5SWCMch/Xd8GAsfqYfIqpn/lDv4tL7bB+Fxm2ZO0Qc4412
         rL7VeIFujt9YcT41PaIpKfUqltinQOTaKm830awPDF5dWV5UGtXOFLwx0UYo36qkJpWr
         WXzqX0B4dzaYVTKIJ4f4aoCzgUZ5sYupt+6d50AU4OU6dqO8I6+zS5O5f1NgUvnGCvma
         aQD8vmIvL3wm0riVvOpyhw07zJUCsEQiK2HW/L8uU8uifrFeXb+ZdwfN6kFDD5F9sdYx
         1Nyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=CrDU6+X00oT2IaqSwTieap275V7Z8zcDlWen9qHZQAE=;
        fh=b24KRTfO6/iNf2vfjt1Zw3c1cKldzboTskqGPVAg0iA=;
        b=QmvM/pFhy4EyxW24edEknlZ9AdxcJanHqZ+ZGXs8vgM6NwQUf0IkT0N3ltYwgV9IOt
         xeJBBF0o6G9rHy/9ESm92dZOJouMUF5M0k/KcpwsxzBcfU2qwvkwcTAXKwnUIvEAVNO8
         hmucd/mJ433e1dfmBqD3O6tt+1imexn8Q8F+tOsGA6wc/MpcTfJ4/2kUGiKLV98eS3ki
         4cJOi6C1Vkz8RNTJXs/LuOItWfRWMsqug9qFCeSaBmu4uglejhLNe+p8RGu6QT6bVgcA
         ZldRdQx9xKktHKAbg4vYRHsmIuHWWdDk6rv+ryQyM25p/vdNwWz+ZzFF7106hyRWMZP/
         87Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752572503; x=1753177303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=CrDU6+X00oT2IaqSwTieap275V7Z8zcDlWen9qHZQAE=;
        b=Acx+d+zup68IHkyRwZ/TRxIsySxXGR2IufukbT4GhX3Z8JfaEgIPNYhy4QCeXzTlku
         NN/8+5BfdWYMJwc1/DY1WCuwQq1WEexcc4P/MNyOhNzMBKFkuZa7LwJeaswsGCpgnw74
         MT6lr+6LsIBCCy35LFKh4mliLg0SkVX0EgYSt7Vph652+VsYFE5Jo7VlQs2lkcBuNAfw
         oj+8bwIgEons86E5Elh99A3Gk0w38IO84Mdh45jckCLyI8LoL0Ok/uyQ/+2XwBnWYyDd
         TzkfBazuMsGjF1YhkCD4x5GBN6qeoKrraWo2d6KMp76jtkU910DV4Jr4yfxLymF7zszG
         PIGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752572503; x=1753177303;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CrDU6+X00oT2IaqSwTieap275V7Z8zcDlWen9qHZQAE=;
        b=djUKmMy+9U6EipBFpfHcDf/oalvEWEo3eoNB9akm4f9p/IHxwBPOgpMrO5rNE/Bdvd
         6SEkeYBJiVNfMJwXye5hqxGS+2mBllJfz3qQuvIoOAYmcrYYWOsc+Ge1yshZTS9I8spN
         XoC+NPCNzzYyQzm9ljaYe0/YM0Wbz0NwP+QTu1bQ3i+G7nXTfUMEm7bx3SbFrKS87Dvz
         1t7f4YQrcjIyPW4DLGkvIyJposLAURO6EJAavuMWPyw/5vR5espujyZQCRKA3V9uy1De
         caCdWmLtpt5cigfWWlpiqbkdw7k7hBiWG2uSRqRJKQCcyhiRrLfn3I67MfABpcW7M2Tw
         WyqA==
X-Forwarded-Encrypted: i=2; AJvYcCWEyOT7gHYjdg3YAqZ9qLvzCDt6H54qex8qE11paUrPLseqhbP4hgKtJD7zkcyNWOTm4L2Pxw==@lfdr.de
X-Gm-Message-State: AOJu0Ywh5YoJBkf6syPBPbiYaXC+7tkWIpLba0B/NDASDD+Px/UDEAd1
	3DFvrNmPSPka1G0itGAR/iXUNZKbZbkW+y9WT/sC5RQmKoR7RaGPH+wW
X-Google-Smtp-Source: AGHT+IGPWGe+B438tA2tUfNPL7mcdStdPPfKyXy3D9JElhN6XkjLJDXjZAt9Y78AAKlrtPCkW01OEg==
X-Received: by 2002:a05:6a00:228c:b0:74e:a9ba:55f with SMTP id d2e1a72fcca58-755b48bf91fmr3169963b3a.20.1752572502720;
        Tue, 15 Jul 2025 02:41:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfUD1eocEpOEWe4wPquC2ETC9RndlLi55SLrllfb1UArg==
Received: by 2002:a05:6a00:4f84:b0:725:e3f6:b149 with SMTP id
 d2e1a72fcca58-74eb4904162ls5075784b3a.1.-pod-prod-02-us; Tue, 15 Jul 2025
 02:41:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXST5sxA1S8/DapezJZ7vzClk8L5DL4yYvEF0sykXTQb/noAYXqyl9S6JFur2oRYLjxSx7mTEQ92p0=@googlegroups.com
X-Received: by 2002:a05:6a21:a43:b0:232:93c2:8851 with SMTP id adf61e73a8af0-236b630e226mr3927494637.18.1752572501407;
        Tue, 15 Jul 2025 02:41:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752572501; cv=none;
        d=google.com; s=arc-20240605;
        b=Pwy5SnZYcLRr8dAKIPXNgraFpvCaFxOeaEF9AFsPXzDkq8wjpcmEv1X8jUS65NXjvu
         4Dm8brXyvpOgmmALQIO2wIVIdHobRgkPAjRBvUDoU4VJ1J8Et/ADWjvxt245lSOIcWWf
         k/rPqpFrv2GLiQtatSYbjO4plVB6h9N1obalR+fcQEx08cBYl8DRY5+YwAGc1HmMKQ8a
         eaUZAEo7R4+YgOdSBYIprBaWqMoIZMJwt+8t/dGhGf68tH5ecYUks4q39vW8RjV37Gmb
         DCdG9I/IWkeDAm4agBErivLH5/fYkyJDgIqqLHwne/1BdT+tFOSX1hKwnbN8K3IKMvWs
         YccQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=5SjDOtjzW9fZx4Am+5lLRHubgcbDf0fDM13w8lVFCws=;
        fh=lKEiWUJJGfmzVz91uuKceao8S3nQTpLRabFMJzVnNTM=;
        b=VgYfTTwpgpPM39uAGj9tgl1wPuIsJ1ocIWviOwF/RNWXPCAJ4zKK5psB+3Wq4TfMpL
         O+c08ulBmU0LUlADgJlzwQKYw4sm+gH4+gi2uAlg1qSy2ywQ81SQXYa6xgQmLse7bMhE
         LzlR1LEQ7FGSSPbAKHMgvvJm4EcqoY57fVz6npad8jJRHSByZeHUdm9wrl4WllNHJ1BG
         2ZtEyYtgLvXwWfxXaLPn2vP2OePPB4zMs7GZeR5/kT2uu3WVg/Pms6hqaFo+CbHVcihe
         QQSTpqufI+m8nSdv/gUZ34LIhCTv2XGSvHiwARhK8TYHIFuleLTuT+hkXHf+k7HmGhBz
         b3iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
Received: from SHSQR01.spreadtrum.com (mx1.unisoc.com. [222.66.158.135])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74eb9fb0445si513684b3a.6.2025.07.15.02.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jul 2025 02:41:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) client-ip=222.66.158.135;
Received: from dlp.unisoc.com ([10.29.3.86])
	by SHSQR01.spreadtrum.com with ESMTP id 56F9eb1Q093836;
	Tue, 15 Jul 2025 17:40:37 +0800 (+08)
	(envelope-from haiyan.liu@unisoc.com)
Received: from SHDLP.spreadtrum.com (bjmbx02.spreadtrum.com [10.0.64.8])
	by dlp.unisoc.com (SkyGuard) with ESMTPS id 4bhDb50sFvz2K4cJr;
	Tue, 15 Jul 2025 17:36:17 +0800 (CST)
Received: from BJMBX01.spreadtrum.com (10.0.64.7) by BJMBX02.spreadtrum.com
 (10.0.64.8) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Tue, 15 Jul
 2025 17:40:31 +0800
Received: from BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7]) by
 BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7%16]) with mapi id
 15.00.1497.048; Tue, 15 Jul 2025 17:40:31 +0800
From: =?UTF-8?B?J+WImOa1t+eHlSAoSGFpeWFuIExpdSknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: Miguel Ojeda <ojeda@kernel.org>
CC: =?utf-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>,
        =?utf-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>,
        =?utf-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>,
        "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "rust-for-linux@vger.kernel.org"
	<rust-for-linux@vger.kernel.org>,
        =?utf-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?=
	<shuang.wang@unisoc.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        "Alexander Potapenko" <glider@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>,
        =?utf-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?=
	<arve@android.com>,
        Todd Kjos <tkjos@android.com>, Martijn Coenen
	<maco@android.com>,
        Joel Fernandes <joelagnelf@nvidia.com>,
        Christian Brauner
	<christian@brauner.io>,
        Carlos Llamas <cmllamas@google.com>,
        "Suren
 Baghdasaryan" <surenb@google.com>,
        Jamie Cunliffe <Jamie.Cunliffe@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>
Subject: =?utf-8?B?562U5aSNOiBNZWV0IGNvbXBpbGVkIGtlcm5lbCBiaW5hcmF5IGFibm9ybWFs?=
 =?utf-8?B?IGlzc3VlIHdoaWxlIGVuYWJsaW5nIGdlbmVyaWMga2FzYW4gaW4ga2VybmVs?=
 =?utf-8?Q?_6.12_with_some_default_KBUILD=5FRUSTFLAGS_on?=
Thread-Topic: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Thread-Index: Adv0awkF3quLQs5+RfaRTr3Yr7SnUQATGr8AACy4DEA=
Date: Tue, 15 Jul 2025 09:40:30 +0000
Message-ID: <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com>
In-Reply-To: <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.0.93.65]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MAIL: SHSQR01.spreadtrum.com 56F9eb1Q093836
X-Original-Sender: haiyan.liu@unisoc.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as
 permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
X-Original-From: =?utf-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
Reply-To: =?utf-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
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



> -----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
> =E5=8F=91=E4=BB=B6=E4=BA=BA: Miguel Ojeda <ojeda@kernel.org>
> =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2025=E5=B9=B47=E6=9C=8815=E6=97=A5 =
4:05
> =E6=94=B6=E4=BB=B6=E4=BA=BA: =E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu) <ha=
iyan.liu@unisoc.com>
> =E6=8A=84=E9=80=81: =E5=91=A8=E5=B9=B3 (Ping Zhou/9032) <Ping.Zhou1@uniso=
c.com>; =E4=BB=A3=E5=AD=90=E4=B8=BA (Ziwei Dai) <Ziwei.Dai@unisoc.com>; =E6=
=9D=A8=E4=B8=BD=E5=A8=9C (Lina Yang)
> <lina.yang@unisoc.com>; linux-arm-kernel@lists.infradead.org; linux-kerne=
l@vger.kernel.org; rust-for-linux@vger.kernel.org; =E7=8E=8B=E5=8F=8C
> (Shuang Wang) <shuang.wang@unisoc.com>; Andrey Ryabinin <ryabinin.a.a@gma=
il.com>; Alexander Potapenko <glider@google.com>;
> Andrey Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov <dvyukov@google.co=
m>; Vincenzo Frascino <vincenzo.frascino@arm.com>;
> kasan-dev@googlegroups.com; Greg Kroah-Hartman <gregkh@linuxfoundation.or=
g>; Arve Hj=C3=B8nnev=C3=A5g <arve@android.com>; Todd Kjos
> <tkjos@android.com>; Martijn Coenen <maco@android.com>; Joel Fernandes <j=
oelagnelf@nvidia.com>; Christian Brauner
> <christian@brauner.io>; Carlos Llamas <cmllamas@google.com>; Suren Baghda=
saryan <surenb@google.com>; Jamie Cunliffe
> <Jamie.Cunliffe@arm.com>; Catalin Marinas <catalin.marinas@arm.com>
> =E4=B8=BB=E9=A2=98: Re: Meet compiled kernel binaray abnormal issue while=
 enabling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS
> on
>=20
>=20
> =E6=B3=A8=E6=84=8F: =E8=BF=99=E5=B0=81=E9=82=AE=E4=BB=B6=E6=9D=A5=E8=87=
=AA=E4=BA=8E=E5=A4=96=E9=83=A8=E3=80=82=E9=99=A4=E9=9D=9E=E4=BD=A0=E7=A1=AE=
=E5=AE=9A=E9=82=AE=E4=BB=B6=E5=86=85=E5=AE=B9=E5=AE=89=E5=85=A8=EF=BC=8C=E5=
=90=A6=E5=88=99=E4=B8=8D=E8=A6=81=E7=82=B9=E5=87=BB=E4=BB=BB=E4=BD=95=E9=93=
=BE=E6=8E=A5=E5=92=8C=E9=99=84=E4=BB=B6=E3=80=82
> CAUTION: This email originated from outside of the organization. Do not c=
lick links or open attachments unless you recognize the sender
> and know the content is safe.
>=20
>=20
>=20
> On Mon, 14 Jul 2025 03:12:33 +0000 "=E5=88=98=E6=B5=B7=E7=87=95 (Haiyan L=
iu)" <haiyan.liu@unisoc.com> wrote:
> >
> > After I delete the rust build flags, the asan.module_ctor binary is rig=
ht and kasan feature works fine.Could you help check why
> KBUILD_RUSTFLAGS impacts kernel complication with kasan feature enabled a=
nd how can this issue fixed?
>=20
> I assume Rust is enabled in that kernel, right? Or do you mean that someh=
ow removing those lines from the `Makefile` makes the issue go
> away even if Rust is not enabled?
=20
Rust is enabled in kernel, and rustc version is 1.82.0. I want to know why =
the pacisap/autiasp are not in pair.

> Could you please share your kernel commit and the full configuration? Fro=
m a quick build arm64 KASAN in v6.12.38, I see the
> `paciasp`/`autiasp` pair in one of the Rust object files:

The commit changes the fragment and diff is:
+CONFIG_CMDLINE=3D"stack_depot_disable=3Doff kasan.stacktrace=3Don kasan.fa=
ult=3Dpanic kvm-arm.mode=3Dprotected cgroup_disable=3Dpressure"
+CONFIG_KASAN_GENERIC=3Dy
Only two rust-related global variables in fmr.rs and layout.rs have this is=
sue. Their asan.module_ctor complied binaries are wrong.

>     0000000000000000 <asan.module_ctor>:
>            0: d503233f          paciasp
>            4: f81f0ffe          str     x30, [sp, #-0x10]!
>            8: 90000000          adrp    x0, 0x0 <asan.module_ctor>
>            c: 91000000          add     x0, x0, #0x0
>           10: 52800601          mov     w1, #0x30               // =3D48
>           14: 94000000          bl      0x14 <asan.module_ctor+0x14>
>           18: f84107fe          ldr     x30, [sp], #0x10
>           1c: d50323bf          autiasp
>           20: d65f03c0          ret
>=20
> But I am definitely not an expert at all in this, so Cc'ing KASAN and And=
roid maintainers:
> https://lore.kernel.org/rust-for-linux/4c459085b9ae42bdbf99b6014952b965@B=
JMBX01.spreadtrum.com/
>=20
> Cheers,
> Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
34f4f606eb04c38b64e8f3a658cd051%40BJMBX01.spreadtrum.com.
