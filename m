Return-Path: <kasan-dev+bncBDW2JDUY5AORBNMT6WPAMGQEJQOK4SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 798DE68A0DC
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 18:51:50 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-5065604854esf57663477b3.16
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Feb 2023 09:51:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675446709; cv=pass;
        d=google.com; s=arc-20160816;
        b=JJyAfWutSYePbF0NmVk8grtziCwQ0ew+V9LkAXaMgMyAT/dbP3s1aTzuvPR+chcCnj
         namdIcz6FmN01dxkmkzETtWyrfeSIIJcbdy+K4atk+X1MS097zMTjW2KfnKcXQJL0uUS
         w/Gj60wGzZOdLqaJQRL7TFW2m/1/vhgYZxAEEm3zR4/WoA4igXckx7/voInJyLe1zvt4
         yBN68XNa2PIMZ1bufVqzPeytpyS3C8Akm3LZIGJL157xlCV+TCleyRzYbFB6tdV1GxT7
         8X+JCrxUr24koZoH7ABpgtabgENWKBJqG1XujJ9MqeDeHY/3vxkCHJxNeMCKW7W42UGQ
         xRdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7Z+JxapBRsjLA1WUJYbKLVXoQeEWxmmbYZPyY/urMWI=;
        b=snD7KLUIDP7Fcd93GkyKcAA/kB/ODLRH6wNRb45VDZoYrQOLZpfSVMUpAMvPN4PD3/
         BrFMmItWAZLImLKAOmp095JOf5fzJ9ZrCnHm/HFj/aCK3NhiORpty1OIqapGAIqLWZCo
         xksE9CFUUzqmXwSQYjqZEoUYCKAi1lJe6pjVil1gVOHnV1bWtNMo9nm5atmBpP5gzcDU
         A8lCV7k4jya1YVfZi8WGwayYa5VxSUc12PghGNZBLsCqqgJfYcjk7ASAPiTtGfgH+/Ae
         NLf3s5FXbsxNRp9YqbcHCfnAYqxwV4g1lfV4+5HZm5i6e/3jtCma+gValbsXUWDJn7mi
         fXow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="CigtSY/x";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Z+JxapBRsjLA1WUJYbKLVXoQeEWxmmbYZPyY/urMWI=;
        b=CWnUMAkefoy2DZreIOLdjcMs+zCiErJiC6CrIr1vWIKe5+b21Obon2aBJVB0ZUyVNH
         DASOvdBdwdtVzlIg77JlEJWLZwDF93y04j/UKxWr3GnnrtPqNIv3bsgk/MJzGFZpK8G3
         D1TrI8gc/K0drYgMUfL3NtWVon6WiB+jPoTXotoXue2dsS0ZXCiafigXrQ55QCN08QCT
         gVqmUZVeGwuAlNU/f6D+1fOxI3x4dqg7K61es8F+xriGa69+BlW2k7NhVM1YNn8CEim5
         ofLFm+MLTlN3uOwijGyNHxmq8tn/ThaXL3jN8yO2M+ApP1gNZLw9pkBRxbMH2xJEu7rz
         XUFQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7Z+JxapBRsjLA1WUJYbKLVXoQeEWxmmbYZPyY/urMWI=;
        b=JqTaKf7fu+Z/qJTTFhdM8GP1drzPhh8RwkCfWNH9hBEL8TKOoMR2MBxeRv7vknc88M
         tfXyOfuHRBF2GAh+mo5I76tBC3N25JkYH5La9ZQtg+kkdtW6og6zsSTYBrY6JOApUzPS
         xS3g/7Sy+zcpiWPKJeLJQR+1zegon7EiBJHD6TprkOu01jvEGVIBSPmWDp0LI9j3XUyu
         N2CMAbu5e0msUGxCP7o/q4kTbyh7q5yau1eiM/uyMbnNJwfnOenU3Bxi026w2tt/uYP0
         /71wgdgMM0Vi0Fhf92uouDeF5+/9GjMgnKPuKoIkWRHTRYCy0JNXe8GLri7NDErYp9+d
         Naag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7Z+JxapBRsjLA1WUJYbKLVXoQeEWxmmbYZPyY/urMWI=;
        b=47dmcYqwzfwFhk/hUn52yzFw59e6fK9vnPuj8dFqrYLk8ZR1GopkQRHIl46IW0SSOQ
         6IE45gmz8yNHWhlNaWfyvXsacO38AmtoyoiHLOYZMICN7QhsqSBR6z8CCaS5l+WuN9eg
         IO0VQjMqc8pGbQpqlfHchX2k7fRtzF1dRTEH6ri21fy6d+Nd3Sjk2e0W1FLYmZkDhbDV
         MhgAxhcttUVZHYVTX4SXUMQX2ErAjep8Uls0WFHE2RP0RFIt3X1ay4Y34MxJoYf8trRV
         0rJICraytkHVW+7497YugWiwg1cGO1gOxcWKc4+S/W3DOtJi6LLNECwSq29qFPlxg3Og
         xzqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWEB9WnuV2c4q2qQBnDjEq0WfVhF3/caEEEScZzmzGVpL04S9ZI
	Ch+UjcXInBCoKNY0rcbDDPY=
X-Google-Smtp-Source: AK7set8EfvwPCB5joqiSc8zpSH7BD6fqr5pMzljeyKQlX42OYfRisBvTMzqHDWo3m/MccSLpR0dI4A==
X-Received: by 2002:a81:7387:0:b0:500:550f:38ca with SMTP id o129-20020a817387000000b00500550f38camr1155981ywc.165.1675446709228;
        Fri, 03 Feb 2023 09:51:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7749:0:b0:857:368a:b5d with SMTP id s70-20020a257749000000b00857368a0b5dls3370419ybc.5.-pod-prod-gmail;
 Fri, 03 Feb 2023 09:51:48 -0800 (PST)
X-Received: by 2002:a05:6902:352:b0:86d:4055:18b1 with SMTP id e18-20020a056902035200b0086d405518b1mr1497437ybs.19.1675446708651;
        Fri, 03 Feb 2023 09:51:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675446708; cv=none;
        d=google.com; s=arc-20160816;
        b=I+loUA4PEMFtWITTYbCJU4ZONWaUpmxckqatFAdu9wvlyfGRblqK22KvxGkwXq8WOK
         28/klKMVrXAnh6kZf9YXtgsM1bTQBy2SCOj8fsL/k5LSqCUjlG303Zwo776UgJlWbDNi
         bpj4gBZNo7+ipgAvT26cVDQ/fTOBz8Avta3VduCd3j7+mX2ZL7l1mejiga6072y4cDL2
         nEQ5rOV3+vxRUwK0aHQ2HEmIM8Do99fCe5Y1llDSHk8lQw5ZLwhWwEfhPApg8U8NUhTV
         4WBprT+ppqCwLkjJr6RsPBP0qREiMHQwg7velOhLjcNXSHx+lytExCm8ulY+A29cjrI2
         lwIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YmrRk5Ppmpmqc+Uhn8+9WvaDSzY/AIuZyaXSdzJWtoM=;
        b=j1fagZpr6KUhYa6qWr0AVFSIWswNeZMt9oZPYXG5C68mkE9HDFyWmuu+K9LygtGsNo
         QepK1v32DcxBfz7gXoaT4fmxURi9BjDHQLjoZzBxGf5C1HOBLe7zJWfb33GY9DPgUels
         GAUaI6p8jjGb/l0w+MUyeqYOzlKhzqAlfOSOIJMqO/JMhz8v9LW7w8a9mVC5PAiAaXTY
         Uhh2OgR86J4H2iILD1ymLccu9erobrAlHgvd21MxEZipytnu3KX8wlUWmc819OkgVR3Q
         fg5gK5kxm3ZETQNQbbvsbLT0nkxKLSt3mn6gxaQ+wbzHwGcVhSgeyaq23p33zW0j4Ncq
         y7bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="CigtSY/x";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 140-20020a250292000000b007ddb8337f72si328105ybc.1.2023.02.03.09.51.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Feb 2023 09:51:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id o16-20020a17090ad25000b00230759a8c06so2681586pjw.2
        for <kasan-dev@googlegroups.com>; Fri, 03 Feb 2023 09:51:48 -0800 (PST)
X-Received: by 2002:a17:90a:fc2:b0:230:8094:4dcf with SMTP id
 60-20020a17090a0fc200b0023080944dcfmr298909pjz.37.1675446707849; Fri, 03 Feb
 2023 09:51:47 -0800 (PST)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com> <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
In-Reply-To: <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 3 Feb 2023 18:51:36 +0100
Message-ID: <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and page->flags
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, "pcc@google.com" <pcc@google.com>, 
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org" <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="CigtSY/x";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Feb 3, 2023 at 4:41 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> > Hi Kuan-Ying,
> >
> > There recently was a similar crash due to incorrectly implemented
> > sampling.
> >
> > Do you have the following patch in your tree?
> >
> >
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXir=
PMSusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNT=
JE5Jx$
> >
> >
> > If not, please sync your 6.1 tree with the Android common kernel.
> > Hopefully this will fix the issue.
> >
> > Thanks!
>
> Hi Andrey,
>
> Thanks for your advice.
>
> I saw this patch is to fix ("kasan: allow sampling page_alloc
> allocations for HW_TAGS").
>
> But our 6.1 tree doesn't have following two commits now.
> ("FROMGIT: kasan: allow sampling page_alloc allocations for HW_TAGS")
> (FROMLIST: kasan: reset page tags properly with sampling)

Hi Kuan-Ying,

Just to clarify: these two patches were applied twice: once here on Jan 13:

https://android.googlesource.com/kernel/common/+/a2a9e34d164e90fc08d35fd097=
a164b9101d72ef
https://android.googlesource.com/kernel/common/+/435e2a6a6c8ba8d0eb55f9aaad=
e53e7a3957322b

but then reverted here on Jan 20:

https://android.googlesource.com/kernel/common/+/5503dbe454478fe54b9cac3fc5=
2d4477f52efdc9
https://android.googlesource.com/kernel/common/+/4573a3cf7e18735a4778454262=
38d46d96426bb6

And then once again via the link I sent before together with a fix on Jan 2=
5.

It might be that you still have to former two patches in your tree if
you synced it before the revert.

However, if this is not the case:

Which 6.1 commit is your tree based on?
Do you have any private MTE-related changes in the kernel?
Do you have userspace MTE enabled?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfa%3DxcgL0RYwgf%2BkenLaKQX%2B%2BUtiBghT_7mOginbmB%2BjA%4=
0mail.gmail.com.
