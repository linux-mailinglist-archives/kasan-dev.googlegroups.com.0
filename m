Return-Path: <kasan-dev+bncBCH5HQNQZQLRBQFZ73CQMGQEO75CXHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7558EB49FE1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 05:19:30 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-7725c995dd0sf5115943b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 20:19:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757387969; cv=pass;
        d=google.com; s=arc-20240605;
        b=GLVlMbvRgaDwEreEeCsS7w9lNAJvnIdA7MCnPCaidsyUVH62s78Jqb4KQJrZppDjPw
         EW6pfRMMAn6ymW6Y4JbOUcOFmduJhOT9yzcdLcjPDWG46qlUwqC2jGk/eviloLf9UMQf
         FevlpCj8+7yhcpAD/tucMkBrrubkwWVRDaD6E+z1DKhROazim/H+w31vLamVcY31fwq3
         Ncm+BQoX/y9fWcAXJcHH32dQhK4HtiHEMsg7kkM8hxIkLEp9IZNy3ZJAFPnWf9lYauUJ
         YbiO1fD3cLMl7FYA0HaPn9RKi0PdVeXOOcFQKpnCKBrEYItnPoQw0geIt6zQAcevyOmZ
         Kqfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=ZGJVPFhUsHpWlN32TCDHBenJKbpQoeKFkP0fg/bMOSg=;
        fh=f09ihcUUke8iz8tZb6LCor00g4rZZCPtY5Y7s9xtJYU=;
        b=MKOpbPuIC6qoLNWywKF/j/MTibn90y4J0PSv/ZEtVBFXWVu0sYmLpwYs57GNMQw1NO
         IKsi6KfxE7L3/T8jP4uSpjwDY/FXb+ZUJVKxBF65Y0GJW/hE7II08ZJmNacDh4G2c0qR
         hj5Q4OKMKUylyFlFEq8m7CIf0fyLfof7Ml4UscxxjwSLWPXB4h+pg9yrxPyQcD3xJ27P
         OuN5b02Y9/Mrwdqycw1U/j+gN5P8x6ggxqNAzrfVqh2W+v+yzmq1Se8UaiPaLsmT9tR9
         bl9Xjj9m9e/fVp506lqpifPOyxt8xK0SYKnbiiEfEhssOPz1tN8A2IjhDte07M4mdVz1
         uv1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=p5rougyN;
       spf=pass (google.com: domain of baolin.wang@linux.alibaba.com designates 115.124.30.113 as permitted sender) smtp.mailfrom=baolin.wang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757387969; x=1757992769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ZGJVPFhUsHpWlN32TCDHBenJKbpQoeKFkP0fg/bMOSg=;
        b=drmQwll+DoV4RFrbnwTqQZmV8WJXtfQRUQ6aA4acAoCeZOImKb41kc9mF6GrkHlGq4
         k/UHNQHRMn7rMQ+js9FU/QfuqoDWxWu36hF1bAlOceO6UHstTQoHiBZp+c276PhGPabD
         pdzHiq2zCX3FV4v7GcEjZiFUHLWBKEuYNO1YvvYrKV7SqucEnKBlgjn/L1JTh9+r7hmP
         PceQtQXRashaNZG5kZv04Yx+m5o2c0ACthb4R0PtoF+X3E5hgi3qR6nyu3R3eSYlUg3d
         ilctzUqgBmgOCJ7yQLpzOzmThf8IH8h7CBQPyvceVVIn02rPDmajjf6+tE+1FqjRjxjc
         bUQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757387969; x=1757992769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ZGJVPFhUsHpWlN32TCDHBenJKbpQoeKFkP0fg/bMOSg=;
        b=X6Y0xL/uLvLdT1Q3lXkb9EdweROKHyyeS401e3VkayCEUbcz7Y89/EB8b8/KP++aoy
         PNPIKtKw9BXCxrBR7Co8shiWsy9SgPFkySJto1B5rPjezJ6YSDa7z+O05+uk6dNr98jn
         4FrIBOIHfgFhsIbR4pl6ZU5g1P9caK1S9Jy1YeEeR+cpaOQr4zjFh69N56RiFXNOlteQ
         j8B2P7PY9VS5h///Rorq7PxPHVuNv1eUqAy30lZOtjMld34I2BbUjU5J2xC56umq5H4t
         top4cAPuzIxGGJO14J12LZsj4gSNf6ASj2FCpW1EVQZWOxGnslnLmvWFJC8S8B1qpF5Q
         15jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/PCu1vSSbEnMi6xlNSmcHTNrPyhVhv6iD9KBrc8SJJjq0rLp2wbJxPJVtRwmAoohdCYb3hQ==@lfdr.de
X-Gm-Message-State: AOJu0YwWrke9VDX3wMAOwr8UBKTvL/nxl4Yy94NQdeKB6bWKpw0S0HjG
	ZCSZM6eI08e4aA2iWO/234z4oIQmGJG1YixTrOTQHzoiht6fpwMy5bUp
X-Google-Smtp-Source: AGHT+IE6tAqd7ycAawu+AU+n+GQM3hc3djjfG6RcsiOeNqFHrr+ZEWsVQVNA+SY8chpisR/EHJf3nw==
X-Received: by 2002:a05:6a00:a0d:b0:774:1fcc:5d68 with SMTP id d2e1a72fcca58-7742dccbb82mr13431471b3a.8.1757387968604;
        Mon, 08 Sep 2025 20:19:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcFUDj6/W4nrU+63hS2HTI5VT69Yn6gLGAR4kHEzH43PQ==
Received: by 2002:a05:6a00:39a:b0:772:5add:d404 with SMTP id
 d2e1a72fcca58-7741f03c45bls3134693b3a.2.-pod-prod-01-us; Mon, 08 Sep 2025
 20:19:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhHuYhPDFrUYh5ugDR1GELy56zisVnN2PzHhUPbeEINTzQE20rMuVwEefTrMGcKrJ6q9D2/D/SWcc=@googlegroups.com
X-Received: by 2002:a05:6a00:2d29:b0:76b:dd2e:5b89 with SMTP id d2e1a72fcca58-7742dc9cec9mr14216887b3a.6.1757387967080;
        Mon, 08 Sep 2025 20:19:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757387967; cv=none;
        d=google.com; s=arc-20240605;
        b=V8p3W5Ybf6jrxMGggX4sghypNji0nlvrfZjDAuv5Dfqo+ydC2l7nMIWOUfToeNMBTf
         qtmORlg8zaWdRatIGHBlP7Sr5EWuIYC7/qFVxknBf9Y+R0e2tO0z+tezz+sulfx4GM+r
         g+9oVDMChHtR+jYlUohhEgYxyRwtmLEVWqfGxoBT3Ki8AsSJYkHFJN9tFh/A5hERKHto
         yHMBzkgzL0fEEinHhKnj/hX89oM5Fo6NNbmH9hnFWx8JFLtDKFcsBo+/Lp2hPh63wj0m
         t17qFjaA3vlfxEmNCSHlzNn3cfH35tnp3Bdep6uehDmrIXoI4N2D5Z5nAmdvREBDwMBL
         pVUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=kp/49YwOqYc4XSnECrXc1wc8q5JFsR73JTB4gmB0H9s=;
        fh=xsWrXbDdxvKQG3p0cHatM9LOdtHsMXn/MIVUREci92o=;
        b=CutomXiuxEBXlIk3xVHc9OgO28NSlNWt5PNsv8hIyqOi/Jd1+sDHX5Jg0oRrgbpPDL
         +7+i4AYv3ivEkXnNvogduYQ7nE5DdSvTOYX9zZFjfoiElWdYP1ujfevIQSQPdx23TXo6
         ZDGVgIvIt806JqsTKSQQ0nErCDgkOxnB1T4T8dxTdvo8brIiPe1WEj2S3yaQA/DuaigJ
         nmGe3k83cQ6AYRc3NUk/7w4UXaaZ+dfDW9ZVqhM3RcndruDeBfYwbC67Uko1qlCRbs/L
         ma3/4uQrdy8Rp8Id6xhmg7A7kHcpTq5LJ9AOYa6OylI/PcoPY/8cP5GFipc2XHXP4qKd
         hSVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=p5rougyN;
       spf=pass (google.com: domain of baolin.wang@linux.alibaba.com designates 115.124.30.113 as permitted sender) smtp.mailfrom=baolin.wang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out30-113.freemail.mail.aliyun.com (out30-113.freemail.mail.aliyun.com. [115.124.30.113])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c24si488178b3a.5.2025.09.08.20.19.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 20:19:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of baolin.wang@linux.alibaba.com designates 115.124.30.113 as permitted sender) client-ip=115.124.30.113;
Received: from 30.74.144.127(mailfrom:baolin.wang@linux.alibaba.com fp:SMTPD_---0Wnc5f31_1757387957 cluster:ay36)
          by smtp.aliyun-inc.com;
          Tue, 09 Sep 2025 11:19:18 +0800
Message-ID: <2a08292a-fdad-49f1-8ad9-550bf3129b2f@linux.alibaba.com>
Date: Tue, 9 Sep 2025 11:19:16 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 01/16] mm/shmem: update shmem to use mmap_prepare
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
From: Baolin Wang <baolin.wang@linux.alibaba.com>
In-Reply-To: <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: baolin.wang@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b=p5rougyN;
       spf=pass (google.com: domain of baolin.wang@linux.alibaba.com
 designates 115.124.30.113 as permitted sender) smtp.mailfrom=baolin.wang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
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



On 2025/9/8 19:10, Lorenzo Stoakes wrote:
> This simply assigns the vm_ops so is easily updated - do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---

LGTM.
Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>

>   mm/shmem.c | 9 +++++----
>   1 file changed, 5 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/shmem.c b/mm/shmem.c
> index 29e1eb690125..cfc33b99a23a 100644
> --- a/mm/shmem.c
> +++ b/mm/shmem.c
> @@ -2950,16 +2950,17 @@ int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
>   	return retval;
>   }
>   
> -static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
> +static int shmem_mmap_prepare(struct vm_area_desc *desc)
>   {
> +	struct file *file = desc->file;
>   	struct inode *inode = file_inode(file);
>   
>   	file_accessed(file);
>   	/* This is anonymous shared memory if it is unlinked at the time of mmap */
>   	if (inode->i_nlink)
> -		vma->vm_ops = &shmem_vm_ops;
> +		desc->vm_ops = &shmem_vm_ops;
>   	else
> -		vma->vm_ops = &shmem_anon_vm_ops;
> +		desc->vm_ops = &shmem_anon_vm_ops;
>   	return 0;
>   }
>   
> @@ -5229,7 +5230,7 @@ static const struct address_space_operations shmem_aops = {
>   };
>   
>   static const struct file_operations shmem_file_operations = {
> -	.mmap		= shmem_mmap,
> +	.mmap_prepare	= shmem_mmap_prepare,
>   	.open		= shmem_file_open,
>   	.get_unmapped_area = shmem_get_unmapped_area,
>   #ifdef CONFIG_TMPFS

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2a08292a-fdad-49f1-8ad9-550bf3129b2f%40linux.alibaba.com.
