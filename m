Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBYOIV6SQMGQEMGEAB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 5136574D40C
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 12:58:43 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-403429b3331sf35286301cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688986722; cv=pass;
        d=google.com; s=arc-20160816;
        b=tjW3JjYrc+e/4Wb4jCTosmubHqb8u+Zxh6GHGlRHEFrZHkaOPhdKU9G96q+1sRcTE0
         wRUpjvZCh8wsRFY4qgSeIBRWmsG/HwRXVffK7PXR/LQRdpuzfKpNoA/OCdh/+iCH0x2/
         Ee+Wu8rp5pfeuYylyZEXmgEoUxn53h24vD1VC/1B0i1l3VcbgOzTgtzLUrHCi6XAUqVc
         q3ELTZwGTcMwMoMqARO+BXdY4oa58vooJHX9KVXa7shxCTIFU/ryDyqKPjhEAAzaWdAD
         bl5KYPX2NdhHxSQu3VI9AqfNLgrRUPRnPaqVPDWiahm7i7IqNhw+BSvXdB7M7POi7S+7
         g/Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=tVwr7b4YYvRZuVboPj6krQytOSCjLS5XSP9L4NbaiMM=;
        fh=qaTgcxw1t+XO8eb7IlA13DofIbUHoHaPKRBFwRBPJDg=;
        b=DzE0vqTZ+NpVIUoTel5mZtFN3LmB9pdTV08wsbARK5R9BND78d4KxMCwYpDINGt9+b
         9MV6pThbFqUWqMcMcThBVCzdjNV0hvBtpCC2Zs7apFsrqiPf9sj6MXlhdxWQdv8kr8h3
         iZZmgDTGuBuJPjXfWtWy+6Odv4BxAvjpd0pEqOC9s6dievovzuefvNySrXRwkjoJ7jKz
         wFKlnQUATA3Xp/gnPlCmpxP1Zvl8M1GsbleNyp71PeJ6QUEqP8SzPBBr4afyX6QBom/o
         O7AAXcnr48/2q0l6cUrTrphVI63G0xsuJKyCmzHAQodfBkiYuymRFMuxZqC7WvnH01gR
         Z9yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cKdGo6lu;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688986722; x=1691578722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tVwr7b4YYvRZuVboPj6krQytOSCjLS5XSP9L4NbaiMM=;
        b=oT0Ize9FWlMWOTkHQMBQdM067ZGbEeKxnXS/WE3xWyM6MziR+Ve6c80ODjkiw97cC3
         M4FWXBoJzr+srTYLDlplOww5HACy2sdfE+1AXMMJNPinEkM10UZCHg9XlKCA8+mcJkWy
         K604ZQUUoVFRZBGudTbtZiLsSsO5ZvkHvS4EHj2zlaqnk2I/coHlBc8Wdrwj5ojWVfcP
         lYj9SWZjMc8GdEJ+roo7I28Tzf2u2xWnwTWCjtgOOeXes7XKgsSGA7EeX4SIAOm7E7D2
         BNwwWrkA0QDteVZLADSLSuKFNR1K1gfp5DpslgD7QVGQDF9ToZizgJvdzHdJdR5C7sKt
         E3qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688986722; x=1691578722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tVwr7b4YYvRZuVboPj6krQytOSCjLS5XSP9L4NbaiMM=;
        b=jo7yKbbn8ZXESiVri46Bmc05Y5SkMRT0FgV4gdnV4S7ShEAlVBZEJWYNbADLX6EcuW
         6sQAAUgkbla/XSURIW3PBNpoS7Dx0MTFQHNRCnBYYibEgCN+QYbR7MXH+ToiHvy8RQ8E
         ve5gWYLtgu5UNeKqKNpYFw5GKGgqknGQL7SgYmx7Wd8Y7iD05GbQ5E2mBSqQEnc2E6dD
         3Lr7EWwLInA4u/RGfA9NJOhqWPlbulX/G9nAV6w7MFYc5yxkL9sWhQi/49iIE4VS2I2h
         FhRGWMZ1PTKvdVfl3nVuwNR7cyIfayER8uop1yvdtoNs2ru2xWb1osP+6RzobCqA+3Qu
         xUNg==
X-Gm-Message-State: ABy/qLYZIOfP2VPaMLGljDX5rTMOGeLeNYxfDUZeyngBYiIh/DaKfcjq
	zC6nNqv4DiJimA9Fo8KMOgs=
X-Google-Smtp-Source: APBJJlEoCnZlp8tDEseIczcJFpcbdvMs8R+giNTxOi/njr1vk+4oHtiIem/aS9Jd1ro+xy8louU5ag==
X-Received: by 2002:a05:622a:1189:b0:403:acbc:d1ee with SMTP id m9-20020a05622a118900b00403acbcd1eemr3017153qtk.42.1688986721926;
        Mon, 10 Jul 2023 03:58:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:71c9:0:b0:403:ab5a:9c10 with SMTP id i9-20020ac871c9000000b00403ab5a9c10ls881222qtp.0.-pod-prod-03-us;
 Mon, 10 Jul 2023 03:58:41 -0700 (PDT)
X-Received: by 2002:a05:620a:2844:b0:767:6b08:578a with SMTP id h4-20020a05620a284400b007676b08578amr10472150qkp.71.1688986721386;
        Mon, 10 Jul 2023 03:58:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688986721; cv=none;
        d=google.com; s=arc-20160816;
        b=Z41hgwZUdoQo1nuxtKqeVmGmDL8gjpejs9XTBXttY0UaNGi1H7InwaEJWkHvq2rS2R
         XC9twUEjhe5o4haeNviK2DnPFExHPhWixCDfi25xk47OcgfExxCOI7Lw/RbCNXmfIXSP
         z0ZJRPMgiGspc8fpfibMhGcdJN9tcFuvPTKmlhb87bic11TWi612DeTTdf1+grtGV7aG
         40z/vWF+WiuxVZtbNYw9ErM1HnZ+4pBwLwjGkyQWcN5rzE1p93YfXQRFBEwbF0iK4N7r
         Y96GjxNMLTeVGB2UCgsEg46DvmRKgrg1uuAnxDOjTigcmY5iTMGIMb5l5GZI2pKB1FP+
         cuXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=cJG2s9++f1Tq43C8nTe1vusCTWa1w6VOf0Nc/0qr1bc=;
        fh=ze3n4caySbxAHVqHDChZBUej/9vsC83YAndyDuHgKKU=;
        b=G1vcC7nCV9DPLI0krVSTsogYk+XV5A+W/ZoQRhs3fD0g+JKhfOc+L03IMEgOqxxPym
         2DxRPZGE6nmtU6YxK4htTKUzd/Cd80Xb4nS4mEG6Z9aJ3c7r9+eSZPF4VoTxiRdwz9jt
         itpqLalYb0xv3SFZyY/uaqj/eiJH60evjNX03od6RnoDHkIAi+a/yTIaypMJd9A6EDHK
         9053Ew3LSa81o5uGgiQ+hM3OJHhC7kUsP3XrH+fuLGat8zCoXvXR+oWfWwjNsYoCwWQ4
         3w+i/0pm27dksakYLUBh6t+1E1JUtVT9x2pfNZdoRTihXvLontYp+2ZK+3/AHrQtvorp
         qf+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cKdGo6lu;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id c9-20020a05620a268900b00767644f9b25si524336qkp.2.2023.07.10.03.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:58:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-53fbf2c42bfso3246420a12.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Jul 2023 03:58:41 -0700 (PDT)
X-Received: by 2002:a05:6a20:5483:b0:127:3c6e:fc83 with SMTP id i3-20020a056a20548300b001273c6efc83mr15851991pzk.42.1688986720819;
        Mon, 10 Jul 2023 03:58:40 -0700 (PDT)
Received: from [10.90.35.114] ([203.208.167.147])
        by smtp.gmail.com with ESMTPSA id u8-20020a62ed08000000b0067ab572c72fsm6919768pfh.84.2023.07.10.03.58.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:58:40 -0700 (PDT)
Message-ID: <8bc21e32-fdb0-e1a3-477f-dd660646ccdd@bytedance.com>
Date: Mon, 10 Jul 2023 18:58:35 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.12.0
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
 <CAG_fn=XH8s8JbMKjsyyw_FZhLuoBqAwWU_+hCGyAXwe3wTBCWQ@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAG_fn=XH8s8JbMKjsyyw_FZhLuoBqAwWU_+hCGyAXwe3wTBCWQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=cKdGo6lu;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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



=E5=9C=A8 2023/7/10 18:37, Alexander Potapenko =E5=86=99=E9=81=93:
> On Mon, Jul 10, 2023 at 5:27=E2=80=AFAM 'Peng Zhang' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> kfence_metadata is currently a static array. For the purpose of
>> allocating scalable __kfence_pool, we first change it to runtime
>> allocation of metadata. Since the size of an object of kfence_metadata
>> is 1160 bytes, we can save at least 72 pages (with default 256 objects)
>> without enabling kfence.
>>
>> Below is the numbers obtained in qemu (with default 256 objects).
>> before: Memory: 8134692K/8388080K available (3668K bss)
>> after: Memory: 8136740K/8388080K available (1620K bss)
>> More than expected, it saves 2MB memory.
>=20
> Do you have an understanding of where these 2MB come from?
> According to your calculations (which seem valid) the gain should be
> 290K, so either 2MB is irrelevant to your change (then these numbers
> should be omitted), or there's some hidden cost that we do not know
> about.
I don't know why the 2MB memory was saved, but it looks like it has to=20
do with the .bss section, maybe removing this array affected the linker?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8bc21e32-fdb0-e1a3-477f-dd660646ccdd%40bytedance.com.
