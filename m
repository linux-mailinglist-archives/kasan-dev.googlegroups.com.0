Return-Path: <kasan-dev+bncBAABBLVU4HBQMGQEAMFUO2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EB67B082B9
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 04:04:33 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4ab5d2f4f29sf8461431cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 19:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752717870; cv=pass;
        d=google.com; s=arc-20240605;
        b=H6oaENT7FdktAIk62tohpERMsScAl0Yra0y+sYTfxoNZuMbU6RHx60L7pBYsrMILk2
         Th+ohytzBKV1phJdDk+IF4o5GH09M7wzYQrd1pu/Xops+TzPKgrX3UZK6SExUbyqTAtc
         8J4jD8ohbYk/STzkVuXQXZRJqJ/v9dhxoRz9Wi7p8R7WKQKSujEG0QBpBUkmakHImjd+
         H5qwVc/aUlZeJZO5oWfBks/IMJa8LDM0Y3nuUX5I4yiQQj7BeMq6D023iZAJklOhE6F1
         RIh57QETUtOvHJqCB9qWq7dbCLkplQJCk5tCdJZProIaRf7brRUcog1zfswnJ5OyQ/Bg
         Q3PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :dkim-signature;
        bh=Qwe60SghGK9CAWdlXzVGttvQE/W5xOw7asFGdUfd7JY=;
        fh=rV6C8lSHbzxZqjImpnW8FXlE/tzHXwPx1rhVZC6Jcrg=;
        b=KE1xAP6cXrEwcjlL/RQMfRLdluvxG1IGIUIMOP1+h8zdRQubjSQkwvOtoRSmGo/QDH
         wwdICeNe2mYCWPFJfVltAzoknAIeHiv1Z6A7iKPLPQPxH19TQQjXT6YE7aspIykyaLE9
         tP0PNg//aH3kndgjYrDHps3T/l57x/DFH5rLJZTdnNOLmo2CJQfaS5sO+Od6BwAGLWSB
         O9TQQf44ucYSX712CGO63X8Ju49kD8TiKkbsGGIDABW0l6f4BTrPUC55HSM26R7driRg
         jQOytZILI4GAoFeI3j/YqXmOebpo/t7yhojkI+TpM7nsdMAlhf53F1axbyEl+0l3AyC2
         Wy4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752717870; x=1753322670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Qwe60SghGK9CAWdlXzVGttvQE/W5xOw7asFGdUfd7JY=;
        b=fa+7Kkj6WU52ycYnm5AciKeA8P5eT5VfNr/TIE4Vmn7xr/khV2mtoaLiMltE3rWaqE
         //K0cNNWane2knu6QaTb3C+IfOt3MuMfBrY/BQYMAwNXChaoHehUqQ6S7xW/hvYudUg/
         K96GHhyM8FGCqGKUeXpoaMnjqQB0OFxP4ZbGibSZEPlA4YRUJ1zbLjLTdbm3fRnaT+7g
         KZaYGLrYClLaCugyx1mU5uJ3ijd5SY1hDpAEdudweVoe6aQU8cDus7OM4V/wO99PPYFN
         5Zu/MRwkZLDM3MGh6Tlcxc8lj1dwypcw+4nsKHTc8V+hBqm8fl+DHBevSux2a1MfCZWp
         pViw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752717870; x=1753322670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qwe60SghGK9CAWdlXzVGttvQE/W5xOw7asFGdUfd7JY=;
        b=pHs8nl72iAqLh8hlztwBXbmGncpGtM0SCTweULDgfLmhgg/2smDM1U6MXcrfNo9Im3
         ozwKjp0TVRbhiovZ46d2T5U+hLKMdrI+J5gMwojyG74LuUgY38huoECWnY7D47/C4BHH
         ySrYIR/9w8AyxNXmqdTN8LMmNJKdZjUlevXkZESGucHJDo33jxZjffp8+TdlBHyxxOmg
         X2AR7zPmtAeFtDsl81N68n89fqi1wJNpJFW2HnqkRlfE3CjMkN4nMiTd1oLSanvYpVo5
         lXImTF2pEngisv9RFpz5cWl5Q0Pmv+w5HP1ync1ouaTlJe4Qhnq+UkcdM8sji8CJTeB4
         qqSA==
X-Forwarded-Encrypted: i=2; AJvYcCVYA2cHvdU2Ro974pJF1Iw0ndmmCx53G9g0b1NYxBuLJBabzV0g6fV8yZHg/NuD8cwte4/iHQ==@lfdr.de
X-Gm-Message-State: AOJu0YyGrdGb9nqAhZok2CzMDNn0e908NHWc/aTL5e+HXCuoiU/mElqI
	e4MK7mTaK3qkHZ4J0HgSaaT0TRUZsoBfcTPHMMWIgxt+27hW/Ag6jRos
X-Google-Smtp-Source: AGHT+IFfxJUCepBEGm8Zdvv6z7459ahuoMFoK/RtI/+RJh4u1Efjtqsjx6Bz0xemhghTju46t21uwg==
X-Received: by 2002:a05:622a:181c:b0:4ab:651b:5f17 with SMTP id d75a77b69052e-4aba3cb8770mr15866251cf.18.1752717870398;
        Wed, 16 Jul 2025 19:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcg/Mi3hOLw+7eNwhOs+prXdrRCzbYbpjXGJlPhQqkDpw==
Received: by 2002:a05:622a:199b:b0:4a9:9584:1444 with SMTP id
 d75a77b69052e-4aba1a3b7f9ls8412311cf.2.-pod-prod-03-us; Wed, 16 Jul 2025
 19:04:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXrvk95XfyF/LforZ3e6JPm2BW2sNAtJWNohq+07h5Lw60mHZ6nGoxe0NQ0oZe1XrAmCJP7AJFCqs=@googlegroups.com
X-Received: by 2002:a05:622a:3ca:b0:4ab:751e:9d94 with SMTP id d75a77b69052e-4aba3c48df4mr16090191cf.5.1752717869635;
        Wed, 16 Jul 2025 19:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752717869; cv=none;
        d=google.com; s=arc-20240605;
        b=A/AcUugEzkMgJhTGIlbwki42wZ82OpJhjU+IWJi55u1zctPAf5o6QDL/bsC2VIsCC9
         FBFO993W6wCZ+kOH3m9fcOsovigJyaIK+NkC7Z6qysCZXTKrnyYvfbI1YYxuozE/Ifj/
         1iz8tuvWyiupAS4DARgkqxarr6fUccG4jaaA2bCaiiBEozzfDyNnjVhMhSv1vph7KhKz
         5smN+HTv3NL+dEHZGolTkD1sdEmJkmOYFxI3hd54HnJug2io/TFNviUJ3/AAdbTtqWK/
         kPu0XV7HmXDTHMowEdikCUwUTSUETUKT1yFEJVKYNgEdCtiv7aKCYiXqfeYiverWXXEx
         0FKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from;
        bh=cu/yDUrxST+1uvsl2WRsJcz+fPWrEMdPUqli4QG1bzU=;
        fh=UBxxb/en1S5oSuoRsEG6kMUoYYbr6bJ8L0ujMXafzXw=;
        b=Dh7ZEuREQq0h8PJcguBL3AzYdTnBKvnCzKVk/wA2UigNIr7mH4saTPZUu+oQXcB9hC
         qDMkQM0c5gmM7F8evKlk6hJkFFwv7jmESViwLUu6zTkeYS1Xj+uopd0q+SO6fdOc7VZm
         TvEk2YaDf9kf4Af78YqrtJObhfkVh7IZQcuZSVS8iaqAUaVtdPJTaywBXGra1E/SZpxq
         RK/xlFsuM/hzcej5J1O/Pw+72bMz7h23LSFgjhq7QGjDVg73EbujXaIwdsMrdQvyCVdO
         96VeKZfAuALTjq1j+vCut/KaCdgOSRHll0HDN6TlnD4nCGnFpUVbUb74214t/7x9oXK0
         +Cww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) smtp.mailfrom=haiyan.liu@unisoc.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=unisoc.com
Received: from SHSQR01.spreadtrum.com ([222.66.158.135])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4aba2aeb447si536771cf.0.2025.07.16.19.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 19:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of haiyan.liu@unisoc.com designates 222.66.158.135 as permitted sender) client-ip=222.66.158.135;
Received: from dlp.unisoc.com ([10.29.3.86])
	by SHSQR01.spreadtrum.com with ESMTP id 56H22LlB062816;
	Thu, 17 Jul 2025 10:02:21 +0800 (+08)
	(envelope-from haiyan.liu@unisoc.com)
Received: from SHDLP.spreadtrum.com (bjmbx02.spreadtrum.com [10.0.64.8])
	by dlp.unisoc.com (SkyGuard) with ESMTPS id 4bjGKN62JQz2K925k;
	Thu, 17 Jul 2025 09:58:00 +0800 (CST)
Received: from BJMBX01.spreadtrum.com (10.0.64.7) by BJMBX02.spreadtrum.com
 (10.0.64.8) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Thu, 17 Jul
 2025 10:02:18 +0800
Received: from BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7]) by
 BJMBX01.spreadtrum.com ([fe80::54e:9a:129d:fac7%16]) with mapi id
 15.00.1497.048; Thu, 17 Jul 2025 10:02:18 +0800
From: =?UTF-8?B?J+WImOa1t+eHlSAoSGFpeWFuIExpdSknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: Carlos Llamas <cmllamas@google.com>, Alice Ryhl <aliceryhl@google.com>,
        Matthew Maurer <mmaurer@google.com>
CC: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
        Miguel Ojeda
	<ojeda@kernel.org>,
        =?utf-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?=
	<Ping.Zhou1@unisoc.com>,
        =?utf-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?=
	<Ziwei.Dai@unisoc.com>,
        =?utf-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?=
	<lina.yang@unisoc.com>,
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
        Suren Baghdasaryan <surenb@google.com>,
        "Jamie
 Cunliffe" <Jamie.Cunliffe@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>
Subject: =?utf-8?B?5pKk5ZueOiBNZWV0IGNvbXBpbGVkIGtlcm5lbCBiaW5hcmF5IGFibm9ybWFs?=
 =?utf-8?B?IGlzc3VlIHdoaWxlIGVuYWJsaW5nIGdlbmVyaWMga2FzYW4gaW4ga2VybmVs?=
 =?utf-8?Q?_6.12_with_some_default_KBUILD=5FRUSTFLAGS_on?=
Thread-Topic: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Thread-Index: AQHb9r7T3quLQs5+RfaRTr3Yr7SnUQ==
X-CallingTelephoneNumber: IPM.Note
X-VoiceMessageDuration: 1
X-FaxNumberOfPages: 0
Date: Thu, 17 Jul 2025 02:02:18 +0000
Message-ID: <484211314e1f4a7990a43852db79fb20@BJMBX01.spreadtrum.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.0.93.65]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MAIL: SHSQR01.spreadtrum.com 56H22LlB062816
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

=E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu) =E5=B0=86=E6=92=A4=E5=9B=9E=E9=82=
=AE=E4=BB=B6=E2=80=9CMeet compiled kernel binaray abnormal issue while enab=
ling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on=E2=
=80=9D=E3=80=82

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
84211314e1f4a7990a43852db79fb20%40BJMBX01.spreadtrum.com.
