Return-Path: <kasan-dev+bncBDW2JDUY5AORBGMHSG2QMGQENCHE56Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA7193DCBA
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 02:47:23 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-a7aa054fb2esf105920166b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 17:47:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722041242; cv=pass;
        d=google.com; s=arc-20160816;
        b=b0LcJYZrDWttpHdH4Nub5mqMPY5T8aByaA9BQp3RlPl/7d5Lrio+LmQgXgEgTRNLuX
         AqzTtGs5WFxvnv7OH7tm8VfOcQH/vw52fAVakYgFNpo0HWMYNjrRZ74N9aq1BdrQpBPM
         f9+V0dUjQC5v2B2QE/OP7+bDkzBJE4++FaEvEgYemvJsy2X9GuCP/gy6q8F7DJr5pH2h
         +gcrW4J9gAi+TQS0g3jv2d3kNXjYWp03+xBYjaLpOVeiMgPM0kL9EMeV871tbUKHrNDi
         CONsV1Btcetj2WIrXKRlXTd+G8zXoJsU9PJr3GUhHi/vvEMxRCjp8JZous30TkralAPa
         BWQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=963bbEWwCNLDAFv8w1R/pIQsnvJnyJ3XZg9WaBxCBCM=;
        fh=ppdYlnD0E6afm3YXHS51Lro/pwJJ8jZFPU2jkq9pv7U=;
        b=hQCUKFJZ15vsQ9cqN40Y9nw29AVEe7hjpMKS7O2vEX0Ek+7AATYnLhsFP+dgbSx32n
         6XWZ1kt/3dm47TuRYQj61SHxBYxPF6/B4OfHBlxfg6tj16XaIA3x9wrB7yXxWr3Hqgmw
         2fCdkvhhQUlOxzdRPNhhOUdEyUUSkwPw2fOO0siLGXXr2IWta6OwYnlG1A/zM22MMaTB
         5tjazqENOTgSmwuvoZW7RthCK8JorcuFiOqTrlzqg255taTKtWPme+smByS9D6ug9bpN
         x6uGA5EtQ45J3/cGWwna2EBCGKWZFUwpNH4f6mb5zcFMPYkJK6MJidmZGcyP+utWiZh9
         SBgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GUxGgBku;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722041242; x=1722646042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=963bbEWwCNLDAFv8w1R/pIQsnvJnyJ3XZg9WaBxCBCM=;
        b=EZ1wMfF/ZIC8KfgOn6UZso/DtDuVuiR7GTFv/vunveydW+F9nywYLBHzqKHWsiAZav
         czDRwix7j2bYJxvkQ+g/F3Z3ZebAhav7WAJ29OYPSf+sWZgW8SU5ao/74q/397EbXRZR
         EdQlQzaC8ykscN11NCIefqmMcKnE97lUSn4V8DJvZyTGmWkCdj8Mt+wYrCIsTh9WPtyb
         aITLoiA7koA0KE8HDPrp5Vabe/3goBt0YLiBotew6dgLcffjwqTn6oj4cqi+opoJ2GQb
         ZKC5uUYxN3QKxA0IKkcI6qV85lppOHP//BuvWwAuK3yFJAsVK84/X/LL2NCYiJjCydUR
         tKoQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722041242; x=1722646042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=963bbEWwCNLDAFv8w1R/pIQsnvJnyJ3XZg9WaBxCBCM=;
        b=aCZ/STYVNT+Gwy8laKvbR2p4/L3dzNws8ByVafwsm2jjeSypq29XVb+EcA/3GTFuAW
         cT/zChp7DUbsfaL7kgFuk+In5DgfpbeFbfiEFfekBMWSyieLy1qZ0QGHD8Qr8uttAudN
         Gu6UOJaTgAeENRVZbjCI3JRgGMyt3juvUIhl6M+tcFjKwYyllHkHhoofCa6Vsi+EbMVz
         FIqv3yekshJ5c8CfCUE+nJFNkEYkSvkNzlK/tD5OSOBndjOKDuDoArAC/vRhWHPQflCs
         ++k32LCsDXXg1FL/Io2Qrc1qiE3qkrHcAeDy5LcCPDWnly6WQSmwlX+/PMDdzJnA5HGl
         XWqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722041242; x=1722646042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=963bbEWwCNLDAFv8w1R/pIQsnvJnyJ3XZg9WaBxCBCM=;
        b=S+llHVDtMSJ387UM9/eYlt24+drXFs9nWIjgtB4v/bIYxrnwIjH8vV7a/1aZOFLf7m
         Q4AedetLUdMgDY9HAlsCZUM+h9KzRL+uCcGwB6Sb63WG6Yw3Ew1k/o8nO381PM4pz3Pq
         SErK6skwQQZAbBtT9ugsP8AYGRtSUhgi3rSdj69LiAN8XlaLbV1aa9mDBt6KJUbQl2eM
         xq/UyoVTdBmGlTzBAGsk/tXJKnNEewPFYYAXcHVHtBukdYNb2Ui71XNIbGqlSwYKgbIn
         too1mk5ZYN3i4meIuZDZ+XsV0lNfdDG0JyLBBDuuDpypoKQKON9W/povrjO5AlM5zFfX
         dWtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzrTIaggxJtE7GdkIU1gZPT1xsDJD18fX3pTsfPMswQKNUtXgk4x/YV13wnEkozfQ0C34rRg4OJUH3vV87OMxYxm2wkK/5tA==
X-Gm-Message-State: AOJu0Yx3vDUG3dmc41cJVeUH4JDNWev95NAMahB1xkzgREEpwQvXmr1z
	1qhBggL/ZqdiT7NKPcyOnB4zhThcM7UDzb0bJzrG+omk4uJrQ/xN
X-Google-Smtp-Source: AGHT+IHEEH0ojaRlgvndWby4eQlsR2nj0oi+d0xTWWpmKb/7/MyFggPA/XWDZpnb+704GUFen/527w==
X-Received: by 2002:a50:d001:0:b0:5a1:f9bc:7f13 with SMTP id 4fb4d7f45d1cf-5b021f0e05fmr674989a12.22.1722041241999;
        Fri, 26 Jul 2024 17:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:528b:b0:58f:749f:1c67 with SMTP id
 4fb4d7f45d1cf-5ac0ce09801ls416234a12.1.-pod-prod-05-eu; Fri, 26 Jul 2024
 17:47:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiRmW08vjP0Go0MW5mgWjukej79pHMKv7xRHH8m8gdOL0qquxrxPOkt6utjn4rhkQHFC73ajFWHV+84Cl6DhKNFhjTBVOEnC+n2w==
X-Received: by 2002:a50:ab12:0:b0:58b:1a5e:c0e7 with SMTP id 4fb4d7f45d1cf-5b02375edbcmr703923a12.35.1722041239647;
        Fri, 26 Jul 2024 17:47:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722041239; cv=none;
        d=google.com; s=arc-20160816;
        b=W+Qr5TrXatS0FqGuw1ij8DnNC2bmCRqnW7uTJvVX6OM5SuS2KxulgnSTo1r/kDh5VB
         yVR+A/czcVcu5IdonqteytLxGzUI7IOBqxXPoo2vQpce/jHbgO8Mk8b/6ANXtl/DYoft
         MPx1Dlmn6I6Z5qYCNcJ7jbtVKlw3S6qDBXBy3aknAqz/Fpz87yuXo6CSvgFQKjZjcX2X
         5t/iCErUASyqraGm9VEunobOdpOraWg8AgzHZ2WP/CmKT2qDz699iGGxcWC0EC2E/KD/
         JEpCljA3h7PD1Gfd+St4X3u133iCCL89cK0l3VpnTlsU3fkSn1/YZisr1UTLYo0rTpHs
         7wPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=haWFi9tHwV99EGj7kzUlZrC7I03HetpVb9XSQZ78wj4=;
        fh=beJ8q0sMc80GzhQqtp5Sam5detlSCDglEvQ700jKGzU=;
        b=zTV7y6DcEiaVK4e10mvO4lya53i+3K4OnyAod3dc5mQe0eCxmUUpCeiXcehzwEDb2s
         1HrYX/0hYy25C317KD5LuPr4X+wMFBrjKmlzH9saiuzlV2AGxNHyIBUfRlDq7Ra51+1j
         3FVINjfavoG7PW+mYvNiPKQ8B8fuhkPkbViCZKNN5xynFikaVuf03DSswp1Vw4jtMQ64
         Crh8io8dHJ4+nGZKwI9pcfRf+hKwAC42krjvyHcCyWdL6lMSQFn69ENvFBhhCq5pCMsL
         aTJN7tzFyTI1iADITcs2WqR0kxOiByW5v5umM+xhgCJNvqQeCr2uvtaoIQqqKaj4GEgK
         vRKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GUxGgBku;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5ac63b5639dsi131297a12.2.2024.07.26.17.47.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 17:47:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-369c609d0c7so166256f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 17:47:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBGOo9igtfEvIvVop7JMpgYPxGpeR5I87BGNp5TOKqwq0QNx5pjSFASKIGTHrX9+a1q2qV9C/WzB4DYGPmyG5Gowf7UfvDU6SL8w==
X-Received: by 2002:a5d:5305:0:b0:368:4910:8f43 with SMTP id
 ffacd0b85a97d-36b5cf2549emr916897f8f.3.1722041238862; Fri, 26 Jul 2024
 17:47:18 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com> <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
 <CAG48ez0hAN-bJtQtbTiNa15qkHQ+67hy95Aybgw24LyNWbuU0g@mail.gmail.com>
In-Reply-To: <CAG48ez0hAN-bJtQtbTiNa15qkHQ+67hy95Aybgw24LyNWbuU0g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 27 Jul 2024 02:47:07 +0200
Message-ID: <CA+fCnZckG1Ww9wNcXRuCwdovK5oW3dq98Uq4up-WYOmddA9icA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GUxGgBku;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Fri, Jul 26, 2024 at 3:52=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> > Do we still need this patch?
>
> I just tried removing this patch from the series; without it, the
> kmem_cache_invalid_free kunit test fails because the kmem_cache_free()
> no longer synchronously notices that the pointer is misaligned. I
> guess I could change the testcase like this to make the tests pass
> without this patch, but I'd like to hear from you or another KASAN
> person whether you think that's a reasonable change:

Ah, I see. I think detecting a bug earlier if we can is better. So I
don't mind keeping this patch, was just confused by the commit
message.

Adding on top of my comments from before: I think if you move
check_slab_free() out of poison_slab_object() (but add to
__kasan_mempool_poison_object()), and move is_kfence_address() and
kasan_arch_is_ready() to poison_slab_object()'s callers, you won't
even need the free_validation_result enum, so the patch should become
simpler.

You can also rename check_slab_free() to check_slab_allocation() to
make it be named similarly to the already existing
check_page_allocation(). (I think we should also later move
kasan_arch_is_ready() out of check_page_allocation() into the
high-level hooks for consistency; it also seems cleaner to have all of
these ignore checks in the high-level functions instead of lower-level
inlined ones.)

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZckG1Ww9wNcXRuCwdovK5oW3dq98Uq4up-WYOmddA9icA%40mail.gmai=
l.com.
