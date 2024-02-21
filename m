Return-Path: <kasan-dev+bncBC32535MUICBB5ED26XAMGQEDJSNCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C7FB85D36C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 10:27:18 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7c4a0dc9f57sf624281839f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 01:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708507636; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lu38BRnCWnr4ujo0/i07ljMK7k7Efel4xp9JylNtEF/3r73yVKLa5+XBBcrpq6WEY+
         xtHJwaICv3I2zGvFQXzTsD1cvp9ekcZHOAQKICG/UBHTc2g3i0Y0KUTlOzR/SbLOGetm
         yW6Qy2UWXISM8KnPAKIg+Ycn0520A2zZK5ahXrBGQiAU68k5qoe8vJlPimobcv7SlgJ4
         iuhgtpGwUSoijhtzYutwZJmJ+mmy+YN2Tz9KULgZWoH/beL52RKxIqLDcGZXoUUuorRp
         bsjpgwJR9Ur+45DpHXB353bIpFHJFHH6w8S+Brv96nvoPlbqxkEuiSdCpw8SguF3flJS
         Yo4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=E8Eg0C36FlayXgmPoIUKSqRYYU/puT/LGGEKUp096UE=;
        fh=JWX3vcn73bfM7lvU/LPp1migHxyAAMsmZ5Uxm2IzGl4=;
        b=XD7AfhMER1i3OZ9yWyToiNFun37HTOKbOnCR3DssHbHl73Xzh0ddXL2nFU7tH8yEDC
         hT6jS3qkcaLs8DFTPlILsIY9DO1sngmiC2kPIyAFrGVI9ZHGOR2B6khMFD8V0UffdSsi
         oDJiAi1jTNrqzzV9MPDsCeo48nCerX3i1KJ74pkA5w0sbGKh+Xny6pA/INfyqxr6WC/T
         a6Ujjs4ZPUe2xnJ/cj0piO9rjRkaWyV9eqCJgHQlydCC7baxCh01lzZtbbu8xIYwEVMh
         G2sPxwERnfgoA6mmumvapj8CkBIrdb7MNv4VktSMURYzBjlICiOPyCuGNtspbKc23p82
         aK3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WkASMW3h;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708507636; x=1709112436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=E8Eg0C36FlayXgmPoIUKSqRYYU/puT/LGGEKUp096UE=;
        b=VBi0Io/S7Xf7oxPnuRauY85C2HVhHQC3n6q2Y3VzXu2r3uNXAwJ2TlDO3at8IQQ5An
         F1jiAIwmeDc6df64S6c838xF3tAILyrt86ru6XzOu7iEDKshkfAzNqua02OSH/shYuHl
         iY2n56J6SKBMObbvYbbWo/Vu3o5FALttiouf9jnLLJZ3lhMeqaQqXhpROghSGAwY3ivQ
         ZuHREXtFzOv34aM8Ze6CpeT27U0XhH8Run+XgjaaTlvlOHJpJVxcDLeIYFfOeOI8i7aK
         w4RR/cG7S0zZ5wMe6Dk5itaFAG9Sd/BvRJDp9SxRvjzDbmjtYqVywZV4k+hFy34NHZr4
         WRyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708507636; x=1709112436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E8Eg0C36FlayXgmPoIUKSqRYYU/puT/LGGEKUp096UE=;
        b=UxMrql0yvk/PlSNCf3Db4mzQTNSqkG3dl2+R3IxZ2U3jFWZ0EJMq9lwgpomAQYFLrB
         xaKl0diSK1zYGjagIjv3Ho4yRVDEUBjbsLSsZIvtLyzryuHzbi9lF2YtbbF9eGVK9/lB
         YkVHn2AETDCquc3UUd9JszxTTJYSU9u27SKvtMJLPcFlssvBNBlCiWXKfdp2r6bgdcwv
         RfsHc9CoOETXQYZfRSVR7dlz/B3LteJGDZKQXxx56rlSTc59CCwEkE+x4W2hjM9zVtXB
         iGpAsOkKjDxGlTX0zcGEdcB01PpEUdUxcQpdNWLo3mRSNGLQkcy7msfXsZKjfEf4mAFW
         c1fA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcwBCjOwr0p6uMjt73SQRvVpNZt/WZ8fkrtYnhW+iGPcFJdcsTk7+jDWl8AMvlmlj3BGuVWunyrXtHmf4EdEzBN/+vQJVyig==
X-Gm-Message-State: AOJu0Yw6Kw32D24DthVgULtGskgqmHzqL8j3DioZLa8ZzwmTO5ujgmT4
	OL1U7lqRuTxzqdBv2OjlK9kfnPZEvgRqi4U5g975X9O77gFUtbBC
X-Google-Smtp-Source: AGHT+IE/usW15RmIS5t5qN8NAb2iiNVebZldx2fjyk3c/0SBLSbwxAced+rGLd8+E6ioUly0lTFpYg==
X-Received: by 2002:a05:6e02:1206:b0:365:1d36:91d7 with SMTP id a6-20020a056e02120600b003651d3691d7mr9468703ilq.27.1708507636439;
        Wed, 21 Feb 2024 01:27:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ca7:b0:364:f464:c52b with SMTP id
 7-20020a056e020ca700b00364f464c52bls1585720ilg.0.-pod-prod-01-us; Wed, 21 Feb
 2024 01:27:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDTb2ECtLCQRiutXF2EJOe9RZqkzwCzqadUE4IUviD9cp2iGVH6M3HR9tzJuzWB1Rm6zpkF0GRFaNTzXsvhS0tjsSqPtmQpTyn/A==
X-Received: by 2002:a92:d0ce:0:b0:365:44:1ed6 with SMTP id y14-20020a92d0ce000000b0036500441ed6mr15771580ila.5.1708507635487;
        Wed, 21 Feb 2024 01:27:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708507635; cv=none;
        d=google.com; s=arc-20160816;
        b=reWsjDL4d/RrxU05BdC6ioKJVGSkaKyhTDX5tzxe0miMVyjWiWB2dAryd9lF0SqTQ8
         VE8SGTXL/toUB78rK6RHW0Cfpr+ZnIGYrA4r+a5qIt0mC4iyfrwEd+PU/2AdqL7lLhEN
         L7r51Tgc6iKOJwlz8itCnd4fRjcewBVQYntzJBbvlbfTWIbgscjbDl4v9ptf0j94LrjI
         v0v7mVBhIwrvdkFwf/hWEYrjF/6mlR6OX56pIekqllF636LZ7dhz01LCLrKUD8dmtf+J
         Fudyy2M1bfLwxcdobo+II6xOuIt1vxsed4jvVViacy8sQnUBiF2sFwFcIqvp4JtDJ8jl
         60Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=JqDQzqQUNVGgLXFQ47h2MyrP+vNxqZ2Sfg76FoOL2Z4=;
        fh=qhopI0RY5UK9XkeLTihybEumPL0PHd183E5BtgBik4I=;
        b=WgeS8/ScgxYlYbYnaw60V4yEzJsfI69vue4DKaS7tpj6evHWp34M09wFSiTmyN3ULz
         GQC43Bm8f31BntreUMG1SLEvXYCvnSWeJvTS8guv0C34eu27APHdoo06OADoq4XVlGmx
         aQvQGeAzST/JJmNgD1jL8kkZCvW51Wm1LaJl+jtdQA/RGqQUoWYRlmwQzhEWgODF+Toe
         w5V4QA2hfQoqilZdjjTJKaMDT4eKSU/BgcNaJIgJTErP4F657l3K//99Kwo2URt1fKoW
         H5bxqNzV8WB8e0SylDVKYqWOlOcwZYmE16jfOPNVwo5CtKqu18Je7bTkVRmJoQqyePFH
         4AVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WkASMW3h;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id t17-20020a92c911000000b00364371a54ffsi803124ilp.0.2024.02.21.01.27.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 01:27:15 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-22-JrGJhiVPNG-IClqBJKk9NQ-1; Wed, 21 Feb 2024 04:27:13 -0500
X-MC-Unique: JrGJhiVPNG-IClqBJKk9NQ-1
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-410d0660929so31518055e9.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 01:27:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUgh/1/fK//4mhlJpZO2iEUC0rnpgaC4W89jSyLoOA2KF+jokDVEd8ojjPXZhACd2J7KOEq4iae8F+aYOgj0VyazGKsZXmOfvTPWg==
X-Received: by 2002:a05:600c:19c7:b0:412:5296:9737 with SMTP id u7-20020a05600c19c700b0041252969737mr13136552wmq.12.1708507631848;
        Wed, 21 Feb 2024 01:27:11 -0800 (PST)
X-Received: by 2002:a05:600c:19c7:b0:412:5296:9737 with SMTP id u7-20020a05600c19c700b0041252969737mr13136504wmq.12.1708507631270;
        Wed, 21 Feb 2024 01:27:11 -0800 (PST)
Received: from [10.32.64.237] (nat-pool-muc-t.redhat.com. [149.14.88.26])
        by smtp.gmail.com with ESMTPSA id jj2-20020a05600c6a0200b004126732390asm1837805wmb.37.2024.02.21.01.27.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 01:27:10 -0800 (PST)
Message-ID: <cf5409c3-254a-459b-8969-429db2ec6439@redhat.com>
Date: Wed, 21 Feb 2024 10:27:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/4] mm: pgalloc: support address-conditional pmd
 allocation
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
 Maxwell Bland <mbland@motorola.com>,
 "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
Cc: "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 "agordeev@linux.ibm.com" <agordeev@linux.ibm.com>,
 "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
 "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
 "andrii@kernel.org" <andrii@kernel.org>,
 "aneesh.kumar@kernel.org" <aneesh.kumar@kernel.org>,
 "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
 "ardb@kernel.org" <ardb@kernel.org>, "arnd@arndb.de" <arnd@arndb.de>,
 "ast@kernel.org" <ast@kernel.org>,
 "borntraeger@linux.ibm.com" <borntraeger@linux.ibm.com>,
 "bpf@vger.kernel.org" <bpf@vger.kernel.org>,
 "brauner@kernel.org" <brauner@kernel.org>,
 "catalin.marinas@arm.com" <catalin.marinas@arm.com>,
 "cl@linux.com" <cl@linux.com>, "daniel@iogearbox.net"
 <daniel@iogearbox.net>,
 "dave.hansen@linux.intel.com" <dave.hansen@linux.intel.com>,
 "dennis@kernel.org" <dennis@kernel.org>,
 "dvyukov@google.com" <dvyukov@google.com>,
 "glider@google.com" <glider@google.com>,
 "gor@linux.ibm.com" <gor@linux.ibm.com>,
 "guoren@kernel.org" <guoren@kernel.org>,
 "haoluo@google.com" <haoluo@google.com>,
 "hca@linux.ibm.com" <hca@linux.ibm.com>,
 "hch@infradead.org" <hch@infradead.org>,
 "john.fastabend@gmail.com" <john.fastabend@gmail.com>,
 "jolsa@kernel.org" <jolsa@kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "kpsingh@kernel.org" <kpsingh@kernel.org>,
 "linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
 "linux@armlinux.org.uk" <linux@armlinux.org.uk>,
 "linux-efi@vger.kernel.org" <linux-efi@vger.kernel.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
 "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
 "linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
 "lstoakes@gmail.com" <lstoakes@gmail.com>,
 "mark.rutland@arm.com" <mark.rutland@arm.com>,
 "martin.lau@linux.dev" <martin.lau@linux.dev>,
 "meted@linux.ibm.com" <meted@linux.ibm.com>,
 "michael.christie@oracle.com" <michael.christie@oracle.com>,
 "mjguzik@gmail.com" <mjguzik@gmail.com>,
 "mpe@ellerman.id.au" <mpe@ellerman.id.au>, "mst@redhat.com"
 <mst@redhat.com>, "muchun.song@linux.dev" <muchun.song@linux.dev>,
 "naveen.n.rao@linux.ibm.com" <naveen.n.rao@linux.ibm.com>,
 "npiggin@gmail.com" <npiggin@gmail.com>,
 "palmer@dabbelt.com" <palmer@dabbelt.com>,
 "paul.walmsley@sifive.com" <paul.walmsley@sifive.com>,
 "quic_nprakash@quicinc.com" <quic_nprakash@quicinc.com>,
 "quic_pkondeti@quicinc.com" <quic_pkondeti@quicinc.com>,
 "rick.p.edgecombe@intel.com" <rick.p.edgecombe@intel.com>,
 "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
 "ryan.roberts@arm.com" <ryan.roberts@arm.com>,
 "samitolvanen@google.com" <samitolvanen@google.com>,
 "sdf@google.com" <sdf@google.com>, "song@kernel.org" <song@kernel.org>,
 "surenb@google.com" <surenb@google.com>,
 "svens@linux.ibm.com" <svens@linux.ibm.com>, "tj@kernel.org"
 <tj@kernel.org>, "urezki@gmail.com" <urezki@gmail.com>,
 "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
 "will@kernel.org" <will@kernel.org>,
 "wuqiang.matt@bytedance.com" <wuqiang.matt@bytedance.com>,
 "yonghong.song@linux.dev" <yonghong.song@linux.dev>,
 "zlim.lnx@gmail.com" <zlim.lnx@gmail.com>,
 "awheeler@motorola.com" <awheeler@motorola.com>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-3-mbland@motorola.com>
 <838a05f0-568d-481d-b826-d2bb61908ace@csgroup.eu>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <838a05f0-568d-481d-b826-d2bb61908ace@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WkASMW3h;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 21.02.24 08:13, Christophe Leroy wrote:
>=20
>=20
> Le 20/02/2024 =C3=A0 21:32, Maxwell Bland a =C3=A9crit=C2=A0:
>> [Vous ne recevez pas souvent de courriers de mbland@motorola.com. D=C3=
=A9couvrez pourquoi ceci est important =C3=A0 https://aka.ms/LearnAboutSend=
erIdentification ]
>>
>> While other descriptors (e.g. pud) allow allocations conditional on
>> which virtual address is allocated, pmd descriptor allocations do not.
>> However, adding support for this is straightforward and is beneficial to
>> future kernel development targeting the PMD memory granularity.
>>
>> As many architectures already implement pmd_populate_kernel in an
>> address-generic manner, it is necessary to roll out support
>> incrementally. For this purpose a preprocessor flag,
>=20
> Is it really worth it ? It is only 48 call sites that need to be
> updated. It would avoid that processor flag and avoid introducing that
> pmd_populate_kernel_at() in kernel core.

+1, let's avoid that if possible.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/cf5409c3-254a-459b-8969-429db2ec6439%40redhat.com.
