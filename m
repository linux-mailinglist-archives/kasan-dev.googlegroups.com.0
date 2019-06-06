Return-Path: <kasan-dev+bncBAABBHXY4PTQKGQEVK2DIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F1D937326
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jun 2019 13:42:22 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id y24sf3392148edb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Jun 2019 04:42:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559821342; cv=pass;
        d=google.com; s=arc-20160816;
        b=q/NSTOPBW3cABLcIaOFbOx9sKQVrOkrgxmebN8RNUPrX1NTcB9JxXcxcNs9MzdKjUp
         s0nA8Qyigl9t/srqzkM+FdlN4108zYQKS/RmOj8Po3bZTc0erloqq0wRbBplw/jyH0PC
         Q0RVI75DTLl6X1GLfIVPLy67g67XldVDFiqbLxcTG74sznfZJQrfN7axnvY3qxIJUizZ
         SzPnhAmBH9W+GB/GOatTQId4F4okg/4pDMb+v3tzJW3NkFTGQIjZM1e0oPXlU2mpS1cq
         oxMDNr5/YK9PcDOO8QnwW/sK7OQh7gXREo7f3pHvlwZkUyjHJ154YrDosrDqDnI99SCZ
         UoqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:openpgp:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=tizH9wDGirnZxZrwlLZ5B2pT74yXmtXiOJAnb5icCIs=;
        b=f3fVEtJo9mOlToL3rQxPeGRqcik9G3dx1YEIf3bAJuhguz78dCY8RPdHq+6Zm19sKb
         KFVNyhStGNlukQPZgKrFoCEnckdicjboGYw5sABLRvTCe2TiHOBS1yEm4Es+yPiKXZgG
         YJGXR+B9VkxnOkw7lyC8ieQYgKQZfwmtM3AD03H0kw70fzR5U6JTAiHytp3tllCN0Y1A
         XQY1NNxrljglBwbTOx9dz9bwnDIOIF9b1zkhpCf6VUaU0koTwde0bGzZLoSaIbGRnzzl
         pEr5rj8uv5UIHRHw+aWENkWaht7cBRlIobEyV67tHFQLHd1a2+0N0G0BxVlCxp0Mj+41
         7MEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nborisov@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=nborisov@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tizH9wDGirnZxZrwlLZ5B2pT74yXmtXiOJAnb5icCIs=;
        b=bNKri8MA6nOJHMY7tbQfUlp/TLQUIEO4//XowQlPGd40diARxTR5KE7YGLwrpAR4rU
         aeCXPW1AMHTOf4shdU5pAfFLzXVo0BYCNVx8/LvdfjgWpdLPr/TntO4O9Ajl+/O8tFft
         tEeqedvw+5HwDeQngF9GvX+1rxuYtEmMkwJcc+708vmNrAVmklMKPEKlLEzC8+G8NJ7h
         JfsEl6uAQoxYsWH7a60iwMxatoT80ZnbCKv7xjF48ZLu0/XjuQNrME9CR8r2Q+cTPifC
         sb/KgCHeC5Y5Zokm2Z/Mn0C6obp9Zhe+YcWyMel0FC0lkOGjS6phK/OkL7hkfxTshBQh
         yH8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tizH9wDGirnZxZrwlLZ5B2pT74yXmtXiOJAnb5icCIs=;
        b=nYAfJsX9Jx59GFiomjMtqB8QTFD7XL0Mpz3q9j1tCTNzIbe38fiW+z775iukSYjLYH
         Vwrh5n4sc3nEYF4BNgIctmGnVf1nrMlJIGdhmowE3iA7ZbkZfb23/GCHuIjKt3GodbOV
         1R85QIqtbaTv0PF+Q6+Pxr+bTar9AIc3r9N8H6dYKaAcNk0rukS82w5rb5LL6X8i3zho
         hLkon/ZvG5KC8AYRjC/3KtTqiCwwXc2ii5i4mmCuDCF21PvBakCaecRvZN6W1aOnKYep
         /M730r8mwLiaam6y94fUws2lWsItw7htMihPpBV64uiAeiiS++hZp0n/X8sT8C22DhfT
         xghg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUJr2uMcYrhebxeGIGvXWBW6cSw1VaijOT+AD6hyKONUk9k/SvN
	U1DhesTEkL/cWcnRVqvk/Uw=
X-Google-Smtp-Source: APXvYqxZlY/DiFeoov+iRGCJ2pVV2qgrBOpE/J4UaGiahome2dZSvPDz4gy0PX50pJP8P7PsHxxLHA==
X-Received: by 2002:a17:906:1813:: with SMTP id v19mr27705453eje.109.1559821342268;
        Thu, 06 Jun 2019 04:42:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:94ce:: with SMTP id t14ls357549eda.7.gmail; Thu, 06 Jun
 2019 04:42:22 -0700 (PDT)
X-Received: by 2002:a50:f486:: with SMTP id s6mr15584297edm.186.1559821342039;
        Thu, 06 Jun 2019 04:42:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559821342; cv=none;
        d=google.com; s=arc-20160816;
        b=MDfPYPr+zbqakEIQys88W0L037lAl+HBmGx5r/va/CG0aBQn1/SxT5XM9Hf5hVQSCC
         KQRHjHKWtyQC0qEkxYe0F2v28Aw0B+8lqTacY8c3dNIU3Jg935CU9Im+vdSxJ6Sr6cml
         lwGNrssvCZhlHUPisxUumQ4ZD+oZUt2VOm3lMWofIj8zxpPW32LalcWnwqbzAuMpD0Ge
         QKCykhi7nT3DL8Bradza/TDuTJKocKmifHnhlgaUlAwOM9FZnFoElLMfhEpG/09U/9Iw
         SM7KHV6zZlILcow/tRviQ6W2r3QUmKsfaW0XB7w+b/Bsh5fqwG6xLmXSuzChuRk3cd7O
         Rjtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject;
        bh=bM7V+IsNH9e2NGwdX6e7556rvhKjFZ7ga6J+YXOE95w=;
        b=XbzMOC2Ac2BcVy1JRLRXYo05gK6uXW1ValekhJCbPPw+wS9Va2Ooje8Bmc2MEY/UhU
         whoqXwyB1zhkNyNZiJ7hamiOuH6Iv3Tl7sebIJkOUdFW++CYPfAFUijb3IR+uyHY6+Iw
         KuZhS2ozIrXWERVfC6Gn5nC4nmjHCQna7zLRrvj1oxdbMkvW5rZ2czhNumAtRcBeXH8F
         aWDb2DxgpmHeRSepg8/BU8smnefBOrat/y/Pfx7PyejGgHsscjwZt5ThL+zgjGREavlD
         +ZzELCl9ttNfCVvkhPS4RfIfhSzvqMzd6DFw0QB9/TIIAdKbR0WWvauVPjFqMguwJdll
         xMqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nborisov@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=nborisov@suse.com
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id x27si110733edd.3.2019.06.06.04.42.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Jun 2019 04:42:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of nborisov@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 76864AE67;
	Thu,  6 Jun 2019 11:42:21 +0000 (UTC)
Subject: Re: kasan coverage of strncmp/memcmp
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
References: <448e89ff-d0ab-a3b8-59bd-1ec9e8aea515@suse.com>
 <CACT4Y+a2GvxQrPWk7ShdvtZ0m3cEZdaM8tQ0wxVpW6uJpg+9gw@mail.gmail.com>
From: Nikolay Borisov <nborisov@suse.com>
Openpgp: preference=signencrypt
Autocrypt: addr=nborisov@suse.com; prefer-encrypt=mutual; keydata=
 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
Message-ID: <233d5ddd-c160-27b7-188f-5f6bf27637ec@suse.com>
Date: Thu, 6 Jun 2019 14:42:20 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+a2GvxQrPWk7ShdvtZ0m3cEZdaM8tQ0wxVpW6uJpg+9gw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nborisov@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nborisov@suse.com designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=nborisov@suse.com
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



On 6.06.19 =D0=B3. 10:34 =D1=87., Dmitry Vyukov wrote:
> On Wed, Jun 5, 2019 at 4:23 PM Nikolay Borisov <nborisov@suse.com> wrote:
>>
>> Hello Dmitry,
>>
>> I observed something strange on latest -next kernel. Kasan rightuflly
>> detected an out of bound access on the following call:
>>
>> strncmp("lzo", value, 3), in this case 'value' is set to 'lz' but not
>> null terminated hence the out of bound access. If I change the strncmp
>> to memcmp though and everything else remains the same I don't get a
>> kasan complaint on rerunning the test. Is this expected? That's on a
>> x86_64 vm in qemu and the compiler used to compile the kernel is gcc
>> 7.4.0-1ubuntu1~18.04.
>=20
> +kasan-dev
>=20
> Hi Nikolay,
>=20
> memcmp is supposed to catch buffer overflows. I don't see any relevant
> open bugs at:
> https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&component=
=3DSanitizers&list_id=3D1025947&product=3DMemory%20Management
>=20
> Perhaps the buffer has 3 bytes allocated (even if not 0-terminated)?
> If it has just 2, please provide a stand-alone test for addition to
> lib/test_kasan.c.
>=20

Further testing showed that kasan indeed triggers correctly on out of
bounds condition in memcmp.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/233d5ddd-c160-27b7-188f-5f6bf27637ec%40suse.com.
For more options, visit https://groups.google.com/d/optout.
