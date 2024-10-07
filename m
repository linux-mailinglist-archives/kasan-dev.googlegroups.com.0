Return-Path: <kasan-dev+bncBAABB5VYSC4AMGQEDF6WJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 54D94993529
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2024 19:38:00 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-710e024dbd8sf4207794a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 10:38:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728322679; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zj9lTjHCQYtG5KjScNtBhBgJnRTGqYAYjJtBx4CMXwQPpn2OS+BRrpZJpLO4PxBsaj
         4wxiboCQb5Pk2Kfu3RpK5TnBaJIzcN+E33JyssEQKK9i401zcSrbjT2m/ykhSKEaGgEx
         s1Vb+0IA3vkAwhNizboVIKui0nm0GXdENJKrHcc2xUlGIzbNlzwzcwNJmJT+8E2KbiXs
         isICKGmi31PT4EDPGgxAxedQm+x7h7qzB6zjkzZjuakdw8KBdhgX76E8uVkQVMEslIG0
         bC8BGP8lslgfJ6i2WerZiDE9wjFRAYf376H1afUCiaYzzKkpSwVAMpIF17TfvNVdp8oI
         eFOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/mrtjbsh4QpLGnuTVxgcO4J0IucvmA1lbn0qmks/4DM=;
        fh=EsZMfe/2/yfqkeHg6TlnfcwFlXhyTHJ9unNMN+1BaEw=;
        b=L21XDbCZpPcU9GwZFqbMpUkXhLsMZY3fPEXj6lUnt9aEOdJU3vk+L/gADC0URbuPCc
         taFTAVLMnealKVwEqTyhZH9Npn0bafMu/RiRKLBLqijuodvgHQBx6eozaxjUkRmgufo6
         0wNL9cxo4aA+RNU5b8faxBpoAAzvM9O2FkAIqbBU5GhgNRqz4FTP2ysn1wrr70HJ9XJi
         kxkBikMFoZjcW9CtxV/HchABdUHptmq4PQcMwiCreGdVdNqCXcLyVhoRKXxzj9CvuhDp
         qQyEAFiN/3w1NQUuGSXXOM9iZG3HcZLk6wnzOycjtMK0DhH6hw+yQzHQGyKYx8GfmlwD
         ToCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b="j7tcN/R2";
       spf=pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=melon1335@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728322679; x=1728927479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/mrtjbsh4QpLGnuTVxgcO4J0IucvmA1lbn0qmks/4DM=;
        b=KlOCHl3yBI14KNcIXtbK7NBPBCX2Gkhp1iG/pPw4PDInVq3Mn1GTZR3aAZ+pL1gmCF
         CH1tfuzLJ1m5SAdU/gSqmmPEJiJLErn53mWV5xismxXhwhJVSLhbzyR7K/8A4urwz3jn
         9PdsIipFWzHI+ULKy9a4n8X3CWHP10sbtrwWtNZerKVHC2osk5sANx3AuCGZdUdQB62j
         2SILFsto6IOGyPteTJ/lXWCXBf1T6+AVKIV8I/eHjs43P/k6wFoopVZcizbX9MN5WqIr
         SJaEHpt1zR8JNY/tPqkPLmZuwkCU1grRNWFtnB53a2BqfL2bnniMFqYJLv21GhmtnzPK
         J6JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728322679; x=1728927479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/mrtjbsh4QpLGnuTVxgcO4J0IucvmA1lbn0qmks/4DM=;
        b=LMVKBCpcBcNl1X3Eg54AxFZYSvlnE5SLbPbZdrJJs1he57ktP4NA+6ZCJqKCQY8uO4
         TIeHd4dnLTcZWWs2iDvUnlYt2O5d8nPc2WbMf7El+K404dRlkgjhXIoR3ZFUarf7aEyj
         EPjBPmuNAaLRbeUHlUmYwnM3KkWZNaJcRRo+bFv7LbX2zGqkk7Dv+HpZYZ+LcA5u2f/0
         kwSOo+wP4qG/kkL91vuUxjA/m8sAhWwiic3pfOaB9Zhkc+4gShA3/ROnP9JZf8tBBGXp
         rcgxWJcMAuIH1uw9FwdwOcpRN3TrgskTXvfqSEeoKw8Vd3v2IkbrTG2dsdDUhMGO4LAv
         CqFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLNNEnDo8dzgsASzP6VC6odf+KOpODWVVrJ8QnGhxJQU8rYArynieBuYiBteir5uiHsyF53A==@lfdr.de
X-Gm-Message-State: AOJu0YyUTkSllflGNGCp5ZNUPEriPStk+TrlmLg+XBxDL5/bodag2FLx
	hU53q7HQqz7co72BB7cfU1haMo8dyW3AVOVLy766ntLbISI+QRV/
X-Google-Smtp-Source: AGHT+IErZfBN6RDNISWotJ9Sy0Jf4L16UwepS/9ES89HqGPGPy5fTzvgU3OZJEEmvLaZk5dXkSpOEw==
X-Received: by 2002:a05:6830:44a2:b0:713:67f6:bcbd with SMTP id 46e09a7af769-7154e82ea48mr6179997a34.9.1728322678811;
        Mon, 07 Oct 2024 10:37:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cb16:0:b0:5e1:bdf3:ac19 with SMTP id 006d021491bc7-5e7bd58effbls1778773eaf.0.-pod-prod-09-us;
 Mon, 07 Oct 2024 10:37:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCp5HWlMYg78vxtM5ZKf35Q3JRyklFhmEjfKvLh4ZOxIvCZ1JVLpJtUaWCpPIfSYq8q6ztDEv1JA4=@googlegroups.com
X-Received: by 2002:a05:6830:3488:b0:710:fa02:94b0 with SMTP id 46e09a7af769-7154e7a6842mr8675958a34.0.1728322677962;
        Mon, 07 Oct 2024 10:37:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728322677; cv=none;
        d=google.com; s=arc-20240605;
        b=aW4XVsQ2zKLJML9kV7bnE3/pdqu+T6dJu0iBIKLJWcWH1SpBDJIpq/8+qZkMhiBXEh
         9qWm3rlaAIR5E3wbpEb44aOEzhOGqGGX2z55Aj61gHb7Q8CdtthFk6kD1qzf8B0U/jUt
         tDSHcFT6rkCIaE9HxwndU0q/KCiVFVzWcZDpg2o1ERv3PRF1w1PQDJCRn/LxVSnYz+y0
         wysIlI5W88Rvnp+QLrAyk/Z8XMt//XHGIjO9ofWZ7scEbM2wr533WOhcdtdvRnA/ACh1
         2tNGNt1Sx2ZyBV2Da3L+xxxgwo1ws/w3nNLf1QVYCxjMdFX/BLMqQugKHqZjojOMISQr
         uaxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=e0zWvVAwuNjFVyvqZcLjrFil652es6+3ZXlaMDiTv9Y=;
        fh=EL3rxDxRO3RSQRAAo5oYvRVEj2jezbSa9o+BGDUZqHE=;
        b=grX4BQIEHSmfGa4PKc/Yzvcqfdhw9m6ijBKHpf1MESBnGSN8fu0uBv/Yw2nqxpKNkR
         8V9IcdEj65CYmv2ogE0rAWKz7y1JFvshD672s21ZTj2RXqg5RwDPMhCnW5wJQuAkD1vK
         4BZLN+yBxKaPiIOOokJnnUG8ELgCNvbvudT3Cc6lcnkefeGrtKvZJwUMW60mBu8EbCXu
         0D0zKTZsxiLnHydvIwlJ4sKZ3vnsAWFN0sF8WgDHyLo4nH4jPVy1VG3yicNN2i4HemH/
         Nc2OTL4HyUZ08n1nylwRzR4BXalkQEc89h5elz58W3lfoGYGpcoxxdGp9VjhB/2W8qws
         mLOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b="j7tcN/R2";
       spf=pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=melon1335@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [220.197.31.4])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-715568eb994si202101a34.4.2024.10.07.10.37.56
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2024 10:37:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) client-ip=220.197.31.4;
Received: from localhost (unknown [223.104.83.8])
	by gzsmtp4 (Coremail) with SMTP id sygvCgCXrl5mHARnIWhxAw--.4001S3;
	Tue, 08 Oct 2024 01:37:42 +0800 (CST)
Date: Tue, 8 Oct 2024 01:37:42 +0800
From: Melon Liu <melon1335@163.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: linux@armlinux.org.uk, lecopzer.chen@mediatek.com,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH] ARM/mm: Fix stack recursion caused by KASAN
Message-ID: <ZwQcZvU41vcD-Gkt@liu>
References: <ZwNwXF2MqPpHvzqW@liu>
 <CACRpkdZwmjerZSL+Qxc1_M3ywGPRJAYJCFX7_dfEknDiKtuP8w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACRpkdZwmjerZSL+Qxc1_M3ywGPRJAYJCFX7_dfEknDiKtuP8w@mail.gmail.com>
X-CM-TRANSID: sygvCgCXrl5mHARnIWhxAw--.4001S3
X-Coremail-Antispam: 1Uf129KBjvdXoWrtry5ArW3Cw43WFyftF47Jwb_yoWkWrc_ua
	9Y9F17C345J3W7GwsYkFs3Zr4q9rn5K345GayDt39agFn7t39rCFs5AFZayws5WF45ur95
	ZFs2qa4xtw1qgjkaLaAFLSUrUUUUjb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUvcSsGvfC2KfnxnUUI43ZEXa7IUjuOJ7UUUUU==
X-Originating-IP: [223.104.83.8]
X-CM-SenderInfo: ppho00irttkqqrwthudrp/1tbiNgJxIWcEDJjSDgAAsP
X-Original-Sender: melon1335@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b="j7tcN/R2";       spf=pass
 (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted
 sender) smtp.mailfrom=melon1335@163.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=163.com
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

On Mon, Oct 07, 2024 at 12:25:38PM +0200, Linus Walleij wrote:
> On Mon, Oct 7, 2024 at 7:25=E2=80=AFAM Melon Liu <melon1335@163.com> wrot=
e:
>=20
> > When accessing the KASAN shadow area corresponding to the task stack
> > which is in vmalloc space, the stack recursion would occur if the area`=
s
> > page tables are unpopulated.
> >
> > Calltrace:
> >  ...
> >  __dabt_svc+0x4c/0x80
> >  __asan_load4+0x30/0x88
> >  do_translation_fault+0x2c/0x110
> >  do_DataAbort+0x4c/0xec
> >  __dabt_svc+0x4c/0x80
> >  __asan_load4+0x30/0x88
> >  do_translation_fault+0x2c/0x110
> >  do_DataAbort+0x4c/0xec
> >  __dabt_svc+0x4c/0x80
> >  sched_setscheduler_nocheck+0x60/0x158
> >  kthread+0xec/0x198
> >  ret_from_fork+0x14/0x28
> >
> > Fixes: 565cbaad83d ("ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC")
> > Cc: <stable@vger.kernel.org>
> > Signed-off-by: Melon Liu <melon1335@163.org>
>=20
> Patch looks correct to me:
> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
>=20
> Can you put the patch into Russell's patch tracker after some
> time for review, if no issues are found, please?
Ok.

Thanks!
>=20
> Yours,
> Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZwQcZvU41vcD-Gkt%40liu.
