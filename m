Return-Path: <kasan-dev+bncBDW2JDUY5AORB5NQYG4AMGQERNPI27Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DF869A16DB
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 02:21:16 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2fb50351d18sf2572541fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729124471; cv=pass;
        d=google.com; s=arc-20240605;
        b=fehen+i0c1kjrW+6ZA2z9lJEH3evvXjRBjNv38KjijaTks2SzNgWhPMmd8A9tOJHlj
         5drcATajGCs9XUJiu/yRSd2hmDVXM/2zbX1sPAJGxEFA49+ANNvsESumgEG/jOgEHtp0
         ELY31sxvRispq8qM5QqoW5Z0v/IylS0D6slNWX9f7rIaYCQo8zgYZzp7xAH00aj2fmwa
         i1GDzinPpEwgVbe7HRmYjqmlaJ2EBXKLJruJ2VuYSCPWN7qPp9/GnGgQ3O5Zf4oKCNE8
         CvBIyE8A784EDketrLNAA2WMDY04pTJ3LIDSnUR9JILcUaZgnuYG097EemdmWbmho6gZ
         dIeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JRL1RGeGwC4SfVFuxEwiaSj6i0nhO/GN4NdUuzPT4FU=;
        fh=S8WXasUDF09Kv38HkC5HNYMVKjWvicl2ZhuolD6HenA=;
        b=XcUz3f/PyyMmZBuhd3mLT86myfh5sw6Vi5LW4KHuD9C6SrAF7Yg0PWqOjniJEgYVDS
         i/+/o2NDE2jlzd0rLJf3Y3PmnVT1TwDVIEHt+JYPTr9iYT8gTTXWtbh/v4npZGv2eiLc
         NEDsKB38fy24FBjPuEArwzExBIsCRFkzksWUfs4HdONldzszy306XW6bHyiVXtEAItOR
         h37OSHYJkAgN3E6GDfOoypPdKBMQTa6CnAbvmBiZsX51c4L9g/XqbeVVsLT4rYXvRpAh
         W/d+TVwL4YRsnS6VqmsufWHdGFSzXKPpigNPpShEprNK6QAa7t6AvXYIiXqceSO/l++l
         hLdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XRU7uDah;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729124471; x=1729729271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JRL1RGeGwC4SfVFuxEwiaSj6i0nhO/GN4NdUuzPT4FU=;
        b=UF46wf9Mhjw9Sc1OZa6PsADlO78iXQkXAMzEgHvBY/2w5k+/WQfVba8IDZ6cMRT/vk
         7RCWHeuZsXZMaLYdZEAJrdBU8XQ+b+Gs6H+IEFVBNgMpL8wNj8ydW18iRtjEJlicxDd1
         cur617SWLyMWxwUcPAPIwytJQjnUh6dVMGyeu7zyWSARDqlyaD5cnWNlMTDzqvGSc5qE
         RZTAU6xpFmlY0vf0O0CyKyJaifVyaxbmJQi2GKiQqHAS1GNE+f154Dk95HYLtSGTziUm
         SrSjI3IDRBXX3Axy2vPL4UVAbyRMtvqosb0u9IBfPHOmp9Xk1PqVCnsMgd3RaU3Z6JRf
         fhBg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729124471; x=1729729271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JRL1RGeGwC4SfVFuxEwiaSj6i0nhO/GN4NdUuzPT4FU=;
        b=eJ1oyr6JAHwGhacm7SzoigyqFd+CaLKoTL8Fqa/0xA6yseBQxbVYAyzenJj+ZiQULU
         81Fyb8ucWwLh2k7m0dFklRaxbq/m+HMFkrdewLlXnnlkX4Tfo3q6lpUz4XY3nFDbx+33
         jB4KEmwm5pxLceUjstYE+mZl+ayrN+ZP1aZGFeAqnc7SiYEpMlv9COc3dvbUYgUXxaR9
         9ENfUscrxbxg9l9nt/kKRDqEGtiqKGZrio2DCEOOLMykARgXvzrkDrUPVR3gOl3Kf1ZO
         Z1fVSqZkC/z8HctgVrmBI9Sbbt0DP8PRbHj6X32nOagU+1573QCGqLMoUdojl1ozJ5Fj
         hQNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729124471; x=1729729271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JRL1RGeGwC4SfVFuxEwiaSj6i0nhO/GN4NdUuzPT4FU=;
        b=CJ5l0KJtiR5EqPivCRA0pMMLvFuLqJh5m7T5hIo42eHVR2emJ84Z+H57G9Hvp28rkz
         c3IJL2j8+p6xOwLlWnYYiRRc8dkLzOOYAeKGVKHx4nqan4HTObPaDPjdjzgdonP6xVIu
         tK3o8cu6M30cxxtoDc0BVCQ975511FdBy2qxPLkTMhiXS3s/qFNIlpu5uDGKW/O2qGJy
         WhtVjsb7eB5jj+0ItMUg07aseTpY3EbUrhGMbJj4W6hjXQ3AhXguRRx/yqOS4iF74xrB
         ziY/1ZPvDU2Er2sPif8YNmT6iwKcw8L+an3Vh5WzBgYxreL9siBiU9QqqWDrNat650B2
         swUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXin6V9hfv+GkeOPNGJ+2UegLaQPTd+VFI6ScAqwq7mLSgggyEJ8iGP4jSKq6/lccihJKapgg==@lfdr.de
X-Gm-Message-State: AOJu0Yx0tTLD/n9Ht0eh/0JtnDKCzHbaDFx9+DJdMtrD4/bEcUqGQFZ+
	g44VIJnzdphePEKDgv8G5UwdYUjtkqaXWvW1+Eqf2bl4FqU/SQs2
X-Google-Smtp-Source: AGHT+IEwOTgnR/vq1kHf4hZO0vkRDnxNLBdVZkb6up0kXQKlfk+k3OjxMkE49zrUJXxqkb9IA/CWJQ==
X-Received: by 2002:a2e:702:0:b0:2f7:65c5:c92 with SMTP id 38308e7fff4ca-2fb3f1d93d5mr72927611fa.20.1729124469289;
        Wed, 16 Oct 2024 17:21:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a01:0:b0:2fb:358c:f76b with SMTP id 38308e7fff4ca-2fb6d7157acls1341901fa.2.-pod-prod-06-eu;
 Wed, 16 Oct 2024 17:21:07 -0700 (PDT)
X-Received: by 2002:a05:6512:3ca2:b0:536:7a24:8e82 with SMTP id 2adb3069b0e04-539e54e6cd8mr8473771e87.13.1729124467061;
        Wed, 16 Oct 2024 17:21:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729124467; cv=none;
        d=google.com; s=arc-20240605;
        b=f75XGVwMtDMQtuyUUFRUHUK03acdiWQUTtOaIXHhrYJYwXCe5EfbWW6bgNxpxHD1Uh
         OO+QkNqvyG8GuiS6pqsjbGboIwsVJ00VKnPpPQCHcPyxSdCZrvtcLGjls5B82yZsS949
         gCJlJPo/6+sz4lOZ8XxpwzuG6ya+R1P4jjo2w1Xv1VuxHjy++tqkh/DTTbV/fuxyzrW9
         NUM4UNqqFqYppB1WcrZ7MZD1ZwPT6LOZ1t7W7UYVC06oRMZbBepUu639cwX+Buwth45B
         +70d/iOGdJZlsMQ9YgpL8+o0LTIuQ3A1UDY24L2epZFxxXHJ8PmtoRhCZm5cas24fSvD
         YlTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hF/PSvYiuiuxx/Jgf0MeQ6oHaBF2RQcxfZaHGbh3d6k=;
        fh=WfMxu2TUQ7JAZkAdq55Ge5K8f6aIosL5rUTwhhEqRuA=;
        b=IoKQ4MpzKKaggYwda+o5+ScPqfZGt74beCta9gRZTFWD3OHh/KYEmFIHN51q0uhsuZ
         RrYDxobZRBVxlQaEsHHb7V59DIhSBXfwG11VjLL5Va+vVwxJPMn5dBNoCJP216RdI/SS
         nAMeA8k+WWqxfX5p+IPqrqkGf9YCxxhoBeZ2nTxjEKMYw41xLKbmTKLF+Op5ZoBN++DF
         VQKiwgZxsYLSZqNjty7kNAS+8i2CG9GG641Ll9eBf+AgmdqppDwRnGConNdhuniuooGy
         FgEqaXbQGV8r5vQPatP7OCPjsKhbk2JXnj+lvNOxvb6zu0a4p7Grb0JSpDkQILelzmG+
         HCKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XRU7uDah;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53a0003c51dsi79896e87.10.2024.10.16.17.21.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 17:21:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-43158625112so3493565e9.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 17:21:07 -0700 (PDT)
X-Received: by 2002:a05:600c:3b12:b0:426:6876:83bb with SMTP id
 5b1f17b1804b1-431255e42bcmr157359955e9.17.1729124466071; Wed, 16 Oct 2024
 17:21:06 -0700 (PDT)
MIME-Version: 1.0
References: <CAMF5BpuWUObSvQvTqYaR8qnqWRm5wJ283RPROrsCRrba=bfQOw@mail.gmail.com>
In-Reply-To: <CAMF5BpuWUObSvQvTqYaR8qnqWRm5wJ283RPROrsCRrba=bfQOw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 17 Oct 2024 02:20:55 +0200
Message-ID: <CA+fCnZcvPfs1CQ5s+zHkrheyfZE0tP1pn62-f2NHS501nS+gmg@mail.gmail.com>
Subject: Re: Help regarding a bug
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XRU7uDah;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 16, 2024 at 8:15=E2=80=AFAM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> Hello sir,
>
> I'm currently working on the bug https://bugzilla.kernel.org/show_bug.cgi=
?id=3D215756.
> Filtering out KASAN related stack-frames.
>
> KCSAN uses stack_depot for getting the stack entries so that it can be fi=
ltered out,
> whereas KASAN uses dump_stack, so, I wanted to ask if I should implement =
a
> separate dump_stack for KASAN that would also filter out the KASAN frames=
.
>
> If there is a better way to do this, please let me know sir, I want to wo=
rk on this
> however long it takes.

+kasan-dev and Marco

Hello Nihar,

KCSAN uses stack_trace_save (this is not part of stackdepot, just a
stack trace saving function) to save the current stack trace into a
local buffer, filters out KCSAN frames, and then prints the stack via
stack_trace_print(). In KASAN, we should do the same instead of
calling dump_stack(). And we should also explicitly call
dump_stack_print_info() (which is normally called as a part of
dump_stack()).

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcvPfs1CQ5s%2BzHkrheyfZE0tP1pn62-f2NHS501nS%2Bgmg%40mail.=
gmail.com.
