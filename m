Return-Path: <kasan-dev+bncBDV2D5O34IDRBG4M2DXAKGQEH6XODUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 48CD01027BE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 16:11:26 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id x191sf16325724ybg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 07:11:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574176285; cv=pass;
        d=google.com; s=arc-20160816;
        b=jeSPQ3WEtJS4oUw4xEbK6Moc5V2WdKxtvWjP9FvodABxqTDgTkWTHKsjPQPrNG0/Lc
         MHd+oUIM3hJZFnwlqEiyvOYJsxY5ftuDiEHVpT3RvBJ3dvLxTlNbpuaYTE/xPxqWpBZw
         cnRdKTfJTaXhQQR2fDc0KrHQYkQlauOE3JbXiw0K0dhcPAddqQdtIlvCrbfTijlN7lOV
         K0p91GORoaLfLre4M5oEbbwrW0smdddFABjs6DDvY5jSDRmRNj1Qa3GI525LkaHV58XQ
         5vhJlqxr2pX+pK0wR6iKJOXKNbq/RjvtSqb0vkcD5Ty8+HwX/EOexz0KYcw+KAd33XNm
         ro5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=7ZydX21yc2yDXpUMde07EfBvVozoTzKv28P64OwxfiA=;
        b=jZEQltdb/OE4xjThqEViSWKMp+3tU5s/TfC3YDgHhgXy6YVpeDDRP55jVXE1WJuV3I
         p6/izR9viX/WYMYp+uXEN7miePgy2ytRR8OMQx4yhWMLLQDbuL9ECAHoVFIqCrQ7JSd4
         1ZqTLZFWRszgljTNxCKes04/6FoRBut1k4Soj56fke8RpuJPboBhOPnxYjMKYpDXZ3si
         Lhut9Wj+KX6Ux389skifTRzi3DlOTxB644/rHWz0kR98nUrDL9YCgdinJGMGf8z2euEp
         7g1zEDBb4Uw7Oo+qBAekY0d7OwNMqsOBsuUJjs1jeK9cL1wZUoPVqZS+D5uTe95eEmTW
         G/xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=tS+FH6uP;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ZydX21yc2yDXpUMde07EfBvVozoTzKv28P64OwxfiA=;
        b=Et3rbgz8uTvgdgZPr/efPK41SW7ubzMWQ8V98F7PCZR1G++kMWYWnMlmLpquiIREIA
         gt39dJobCUTJ4ZTRLMoyS3W+eo2Iif1bNId1zOiKlxx2DilspN5ubxeuSRkWh+FMPefB
         TXb0P3vAJw6u1dZAc7Lsmsuen/ohjp/2Rf9IOlNs5evHhj9/w9CU/Y1rWV76ufcGX1cF
         QtjIQAVRzSAjX/NNJbs+SGf2Y7tdiMjvkm7TZ4i/IG4Zl08VAOOXua/tLqEPX+/cE0Z7
         A4UHCl9/IfQBw1r94kbK7+qgmsjyWw9x+yrt/LVMfuzb8FCjgejvocCshIl3a6Zooocn
         MMQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ZydX21yc2yDXpUMde07EfBvVozoTzKv28P64OwxfiA=;
        b=RcdBllEbiQqoo9TYInWk0r1GCuOxMT/EEUs1fGYhMrYlb+a0uX9Hu3k6XyCHeZkMpC
         EZXAvrc6iwwjbiznW/GdsDbY6z261NEihagTlKiTmDL6EKmSu82HW8RDVD/0RmLEBsNw
         IkQFXUJJltiiAXHHXZ5WCwQnRzpt28Xdu/WLmNgB+7Ach4LCZPyux1TSqN6z0QFWdtMo
         qgVqmzMczDvbjUgiFY1ZNXH5+25nOFx/GL+9ptLqQI3NUrfuNLfI1jJiARWd2W/YSi45
         /hm5fSr7Upk4DsLMAKVin6XeushuByYPIoOSX3dcAAUNB45J5g72J4ybFKf1QSX6EjG4
         XBog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqNKY3jg6L2uzUayTeVS61WYcH7HOJ8fDyIfHlwDLvc26Ie9Uk
	4L8b2QPu4rBV4/rECaPRLzU=
X-Google-Smtp-Source: APXvYqwpNlM32rpffH1RKSdnPPJ5QYRkwuKBjKM2AlluSYSPQQhyqUkEvmH0kbJDnZ7JfQdjEoPGAA==
X-Received: by 2002:a25:e08e:: with SMTP id x136mr29457666ybg.383.1574176283954;
        Tue, 19 Nov 2019 07:11:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:ad26:: with SMTP id l38ls2862418ywh.6.gmail; Tue, 19 Nov
 2019 07:11:23 -0800 (PST)
X-Received: by 2002:a81:4e43:: with SMTP id c64mr25490424ywb.319.1574176283481;
        Tue, 19 Nov 2019 07:11:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574176283; cv=none;
        d=google.com; s=arc-20160816;
        b=cB94CkoVKx8UqI5udnkiwTLzqRy3NC8QdvNlZQnhkJxWpFXIXsmSiux7d7p7354zHt
         sTrSQD51Zax9iwMM7D+5DgIgNZfgbWR1tT05fLoTaZ3i85kPS6tR1H4rFUNBuEltUq9Z
         fwHpZUIFZARamH4LadUvKGmSVv3r7mECv1HMJ8x/E3ee0Bz5GtlPDfXmxRVhwktXLeBa
         tNuLMaazjMcs3Up/OoWoJYOIMVkYXTKJe4O3giDkij8+/4URSdRdeIMy0sDVxRKE3yGd
         /SLMOtzwHfyzRHgrVEd5gkQ2PdcgMOgUFqf5lqq724donsZZXVW22sxwaE0LwfVzvrie
         9iBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Tlv1z9IApTP7G1WMZKmi4nhZt6ESnPxSYnU0GkdrTBw=;
        b=TKw3Z2HQrAAXPTcfvhrT5xvTIiu+42CYMeypZ32mzcy5R1WfJBkZfLbfwHW8bt/wMG
         PNq4GTdcnvZnAidaxkeU6LPfj/V9WUB8H05oMAV7VQTVUmsDY+isI3G66zX6uGWLdGjd
         DDth6jBrwqgD0zvDO3/Apd2dtdcmY+LrENF+za03wB/AHRxtLmp9mHczGSQTK/Omyn2x
         YnsWoqtl6q5GskiC0HtdFrXNmQlhlk+ftWd09Vr3k9S66HJRQ06rwEuc9G6MesuBtrXq
         zrEw/exSD20Z7bRNWNU7zIt+boxPLSwyLxeOnv3QpQ81jDuqJdfwaPLNwS5kzZMPGYIc
         Qk7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=tS+FH6uP;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id r185si1155141ywe.2.2019.11.19.07.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 07:11:23 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::5a22]
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iX5A2-00030H-7p; Tue, 19 Nov 2019 15:11:22 +0000
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
To: Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux Next Mailing List <linux-next@vger.kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>
References: <20191119194658.39af50d0@canb.auug.org.au>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
Date: Tue, 19 Nov 2019 07:11:21 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <20191119194658.39af50d0@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=tS+FH6uP;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> Hi all,
>=20
> Changes since 20191118:
>=20

on x86_64:

It seems that this function can already be known by the compiler as a
builtin:

../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in funct=
ion =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]
 void __tsan_func_exit(void)
      ^~~~~~~~~~~~~~~~


$ gcc --version
gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]

--=20
~Randy
Reported-by: Randy Dunlap <rdunlap@infradead.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e75be639-110a-c615-3ec7-a107318b7746%40infradead.org.
