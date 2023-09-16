Return-Path: <kasan-dev+bncBDW2JDUY5AORB6VKS6UAMGQEJNNWUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D7687A315E
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 18:19:08 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1c443fbe739sf760505ad.0
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 09:19:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694881147; cv=pass;
        d=google.com; s=arc-20160816;
        b=SR8zS0DWUn8P7J5iwmc9ecpZGkn5oO1xyu0S+jdDw06UUOrTmfksXMiKCmp4sPvd7j
         M7GDhIZxEUScfoksCSFvRbXJL09JN2iBReVM+JZf7lvjKoJsgwmHjZpZuLzPc/KM0lk5
         VThB7x6EQRwI7guqJvRWFd4mUqFY+4vNf9VLaX6MbOIULWwK37levruOZKLEM9GhKktT
         hkoemjdUG30nkXXt1pWncygJZD+cb1zPa9NNetw+cOIXtDIfWhb6X3pKzJvr9uHRW/zo
         kCEzcZNyxpAh8V65nmzJqdnc5TIon5l9R1zz2rBmAlvWrdwaAJblUYndYewm0r9Cfoa7
         BWdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NLElihzWzVqaYUb9zcTDOGHTa7sJzgdtLNh0VQe5UXo=;
        fh=7RrtDZdsw4fcgSxWHxyBevaZSA/hxPu00gLIY5cK+yQ=;
        b=x5idKUIaYffKTKwuiJSF9+If+DSrfEcpG9PT6jUEJ580YssIqbYCbK4jwFax2yvPFw
         egY25oJpF/S0ThbfuwOmB3p8Gu1hD2jv44vWjCtEU5eFX6mHcBxnqS9yfeJSUk/rT3pP
         wZ4HwF9xNfR029eQEoemxQA1GYlOheQ6NITomk7x7vQnFczoY/dNcV0xR7RAKQVZ9e6v
         SPqPMM0CpbfnEC816IfTiEX1q31GTXSDKpHHqtSaJXCTkt6ekYT86Jro1IE3T7EWjHmk
         bQmQT+gNtGfU6MwDNw+kDEMNQfSGoppSFQSfnvesNlBZgCAC0ZDlvfCi9KiYVkIGuWCO
         SRxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZvDhTR3g;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694881147; x=1695485947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NLElihzWzVqaYUb9zcTDOGHTa7sJzgdtLNh0VQe5UXo=;
        b=hIa/1xxghp3OvnNXjewVS+CVycJXA0Yj/8JT5r5v8ZfFWEwC3zAPskx6EJ+90Vohsv
         9SiDox3C18451EVeBZdt/z+KH2bbV9xLABhubMzAEd9eqxAIlptSNyPLbokSBC3qNDKk
         FgR5xYC6xnNB115fWr9nBfV4q4V2W6yiZasbua80y7G8sMyYdKmQ0sFKjXHTYY4OvD+d
         2Wwzu6XnjsCdLPMP6WtglLZrRrmu/vMg/DrBUhtDo4Je89RphPdtOZoT8mCZ/g61eiCs
         afbDirBaX2nzCjuorkY+Ty/CbvF0jg7nTzYFtdl+2BHHM21tfCR4uxxgr1gNC8iZxtjx
         m2/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694881147; x=1695485947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NLElihzWzVqaYUb9zcTDOGHTa7sJzgdtLNh0VQe5UXo=;
        b=UKi4P7D/8c3RQEHOIiVmOFN8ombSbpRi08GEu6maDoP7Tnz/6us3mN0U4hWYDI/aIF
         0Kf6D2zVBBDzCe5Au2R+NW65qpZAuXVCQPVa4tApte+nBVkQpVuJOboy8h7W8cdSmbI6
         laFa3rvkotFXtvCib4rcipzQOTbGcJRxNM4D+oNS9ELKkNuqh2lN/zLIPNUJRTTQnI3Z
         wY1ic+9fd+3AXg/kW1MF/kbVy1FwjuPiczhZ/EC5vogz7O/NC03NXxJ8ExPpB85ExCgC
         Kvr4keT2w9+w8ApQo0uIhZqzbR+kPO+vh48f5x2o0WNvzg3oA6ZT7DPmLDhTK+g8SovJ
         r0DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694881147; x=1695485947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NLElihzWzVqaYUb9zcTDOGHTa7sJzgdtLNh0VQe5UXo=;
        b=VR2KfT4BDDIDs3SfzbQhjGcfPZ5Bwq9o7E8KdnHmbsvFjeC+jB1z+Twl/kFWZASymJ
         j2/E5TcpYfQv7Lz0O1vfhWhKWo3S4Mq2ZH2zNAibWfOJXuGBFyXTGQ1jR88xh+ZNJUXz
         TJROyW/7ZphaTtlWJKan2WWSuOa/N2vbcvr4Q3+0Ed9pABPklcBNTTUV9Wm5o7QPb3xw
         mC8LPDYe2I61kaaTu4t6gLu0PUgdI+6/DJ6FW48u2PsNk6RUt9mkLJ6JNB3U+nwlALpJ
         7Ohjb0l7EqVThmszfJ1wf4y8UmEQIypcr2MV6dvpPueb6cpoijItFmmGnVq8Io1lWNZK
         0HsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy8vLbNFymzZ/arKqaXNtRMglbdtLt2Z6oYGV85PB4GwLU3337v
	d+1f+/h1LEaKdwdpPUmejTo=
X-Google-Smtp-Source: AGHT+IHj7KZMBt+2USaaFN3opf35WK3ZL9LKPr1qL2d36G8nRWg+1pkmyX3hFIQcCv8/scuFmSk0ng==
X-Received: by 2002:a17:902:e743:b0:1c3:5d5b:e2b2 with SMTP id p3-20020a170902e74300b001c35d5be2b2mr99008plf.5.1694881146658;
        Sat, 16 Sep 2023 09:19:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9e07:0:b0:68a:1ac5:1a87 with SMTP id y7-20020aa79e07000000b0068a1ac51a87ls1805605pfq.1.-pod-prod-07-us;
 Sat, 16 Sep 2023 09:19:05 -0700 (PDT)
X-Received: by 2002:a17:90a:fd93:b0:26b:6e98:29ce with SMTP id cx19-20020a17090afd9300b0026b6e9829cemr3588724pjb.27.1694881145567;
        Sat, 16 Sep 2023 09:19:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694881145; cv=none;
        d=google.com; s=arc-20160816;
        b=GatDETHrGXWNXgUFDJawNkKegBlAO632TFnzsHwfDzB2sPmMDnGy1ZS2NGoH2z1AEi
         N3XgsnDXmPKXC9UUYldRpXPBL9V7dk4MzRe+yirWe8WLwj2E16SabGYyPBhdZpmrWe+0
         Qx5/M+CQFVUsOSNhBw1tah/jG8C9vl6WN9+XJJss1M3QaX1ygyjfBiv3vD+gqVXCM/Ck
         BOGFZaSdNabs4EJH2n/BIFw9UeKT13aQjXTGVVqidP2FwrPRrocFsl7aJFNKxEnS1sD2
         BrbFtcmmelsaeXEqcZpxoJ41k/cfd9ea1VLjrNV1IDniu7yk78OM/mqorqGAOL1yaa9m
         Y81Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h8L+TF2NB2bKIXmFBrFsqsaXp12HgxVOtYytgv3Hfus=;
        fh=7RrtDZdsw4fcgSxWHxyBevaZSA/hxPu00gLIY5cK+yQ=;
        b=up7m1WBIpNEer5YBO7AfsIWzXjpwFT5EsRxI69P1nI+J1LU1bsDuR+fTJOLqstUg8X
         C7D/A7I3ihFG334QhVy1sXeAIFygNufw2aKzGDe+sPWsPWUo+pRk9di5c3JZFuiby6jX
         RElOIBWqGKantE/7Z3UKUpx9529Hlj9H+cEghOUVYS+y+QTjBaCWldDA/+VUneFxVQ04
         7Z7Isb/DEiy71jLlU6Hv4LBs+yk3rsKJGjWr04rBZh9nLxXIJMbEn0C4ybXoxNGcnpak
         O2cBh04SdyegZXQsgH/z0cy1PhgjQZitczWynuBgPKO6qDgEDm9tUZc2/lrV9bXVmt7q
         kJmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZvDhTR3g;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id pm12-20020a17090b3c4c00b0026b48d26530si612779pjb.3.2023.09.16.09.19.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Sep 2023 09:19:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1c453379020so3654255ad.1
        for <kasan-dev@googlegroups.com>; Sat, 16 Sep 2023 09:19:05 -0700 (PDT)
X-Received: by 2002:a17:90a:ad92:b0:274:8363:c679 with SMTP id
 s18-20020a17090aad9200b002748363c679mr3795739pjq.19.1694881145079; Sat, 16
 Sep 2023 09:19:05 -0700 (PDT)
MIME-Version: 1.0
References: <20230825211426.3798691-1-jannh@google.com> <CACT4Y+YT6A_ZgkWTF+rxKO_mvZ3AEt+BJtcVR1sKL6LKWDC+0Q@mail.gmail.com>
 <CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A@mail.gmail.com>
In-Reply-To: <CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 16 Sep 2023 18:18:54 +0200
Message-ID: <CA+fCnZeyS=wr-u4FgJmGLXujcat=oQ+jo-NAt1TtSa_tLEstSg@mail.gmail.com>
Subject: Re: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, kernel-hardening@lists.openwall.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZvDhTR3g;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::630
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

On Mon, Aug 28, 2023 at 4:40=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> > Can't we unpoision this rcu_head right before call_rcu() and repoison
> > after receiving the callback?
>
> Yeah, I think that should work. It looks like currently
> kasan_unpoison() is exposed in include/linux/kasan.h but
> kasan_poison() is not, and its inline definition probably means I
> can't just move it out of mm/kasan/kasan.h into include/linux/kasan.h;
> do you have a preference for how I should handle this? Hmm, and it
> also looks like code outside of mm/kasan/ anyway wouldn't know what
> are valid values for the "value" argument to kasan_poison().
> I also have another feature idea that would also benefit from having
> something like kasan_poison() available in include/linux/kasan.h, so I
> would prefer that over adding another special-case function inside
> KASAN for poisoning this piece of slab metadata...

This is a problem only for the Generic mode, right? You already call
kasan_reset_tag on the rcu_head, which should suppress the reporting
for the tag-based modes.

If so, would it be possible to reuse metadata_access_enable/disable?
They are used for accessing slub_debug metadata and seem to fit nicely
with this case as well.

I also second Macro's comment to add a test for the new functionality.

Thanks for working on this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeyS%3Dwr-u4FgJmGLXujcat%3DoQ%2Bjo-NAt1TtSa_tLEstSg%40mai=
l.gmail.com.
