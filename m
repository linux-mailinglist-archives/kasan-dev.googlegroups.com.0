Return-Path: <kasan-dev+bncBDKIJPMU4QIRB7WDWSNAMGQEC3XJYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A59B8600AF3
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 11:35:59 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u2-20020ac25182000000b004a24f3189fesf3470485lfi.15
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 02:35:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665999359; cv=pass;
        d=google.com; s=arc-20160816;
        b=QcUwVC1WnhabgAy4saXA0/tfS2gPGUU45Kt2EkmyGPwSuqU1Yyip7QF93eKmwqcy91
         zT9KQ0RncaSU2q1TPYCNU9u6xIYS1W38PtKdFqP+16cge9uYuf0WFshbn8VeMELjLLCH
         9fQo9nfOOLRW5f+VrCWaATA+Hqzn15MPWbxhdK6TT33rflYoIwPflJxHaDq31Q2+Rgv8
         ZUnVcY/RP0HzaDzLktCDADgDOJSPQKVoDwUgT0Wn8Tbh0ghjmoMv9Zq9w7/ogipFyBFO
         Z3IZwtP7t/Xnq3etAdbdEGI0cBk3z/LSLJKs59Jb6q+6v9ssUfoNIxJsDLomEYlACPaD
         5ONQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=k1u71Relr/E0kAPaOG5ffBJCSTk+daRnEB/ww8aeoDE=;
        b=Ci0S2nEU8MzQFt+ukjWPfKaAtpY/PligEC9CGwYKt5e+9AtQ2irH/GLY2Lmi0RTiMp
         xLtoU418ht8I1iZ64pPLUPJsVNivDYX5IKJkNBGgjaANacGZGRSoIS8prw3NLmShQSdb
         oEcIP1S/I0rSiLbHEAgW+3XHEAQmut6eC6p2nJrrw18eveTKjmh8H4+hzfA+uF3sB1VW
         XzjRF3bnG7dxrcRyufSo3DPdUG6xFdWJW77XLYWMBM6n5ihP2YGX/QNfAlDLYt+TpsIy
         bQ8dfTYLBD8RfceSVBgFfmt9NOJBuSz7XUZ2XeRJ3wrjeG6+jT+e20EU8Mhqgw5jMScr
         gJ3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=VDo8Gm0J;
       spf=pass (google.com: domain of quwenruo.btrfs@gmx.com designates 212.227.15.15 as permitted sender) smtp.mailfrom=quwenruo.btrfs@gmx.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k1u71Relr/E0kAPaOG5ffBJCSTk+daRnEB/ww8aeoDE=;
        b=hMX8sYgBOGjkt79T/gUI4o8wk6f3F1Cz5oxGYZxbauRKTD2IZhBamrAjc3JrooKYwu
         76lB537ZsV4cksSb8PZeGw5TTsDKosgocfN53d9z0P7IlCv7QDPMI0+cQKdJfkVjUS8Y
         m3Foam0g+z8lEOJqc18886Z3Jq3bS+WRe4cFWeEDFqTbEjVTlZaEuWUOIwfIzr0eSBgr
         rxBU+/nk/s/BFLoOC+YhkoVIbxQw2FuzO8GrWT2OyB1ntNsuOuyUA4VYCulFvCFMBP9/
         I9t8SiQMIJM2C0FTJC0X5xpW38VHnmAgF3kwsIETzGGR8z6K/1dl6fr/N0nRmLEHWyNa
         Y8OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k1u71Relr/E0kAPaOG5ffBJCSTk+daRnEB/ww8aeoDE=;
        b=2E2xXJXbM4FTRetuhIUouXVYebS81NB6OLuMwr64HGA6NetWqVQKynKoqG4gDBCwf6
         iqmTDHCinayCoP3IObTREWtyX9mMYdMNgwvKb0e8ukL8EdDd7sZkiSP3j6sj8YQTWk8o
         NQHpKfGjOEww2EDKPFFg40nRpVHcYE7hWZE3oiunZiu9P1hrlYKzY3OWYIzfGx3sqiLV
         SE+wGqBcl1xBpJPT0G/v/RvCUydqKi1McLvo751uw8T1B1d1JBH5joJuc6v0WTeWQtvr
         GZJxWUC12IL2Qf1Tvp/+nlpn6QpK13Cuan+5eaWlTo2NjoGO+7uDK6ril2ttFUOcTgpj
         29Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3XhBEmSRdSveIwFnfUgqZ+6V4nSNxSCBol9Kauz1T7X+o0vMoL
	rEUn6CQqqNKEgsAMTxV2AeM=
X-Google-Smtp-Source: AMsMyM6I9w9RKaoD/g6Sqyc0Bu1frPivuAzgLKVRMXH9DcaPb2lXTsR1LCuejbusuNXAxWemm+s4rQ==
X-Received: by 2002:a05:651c:228:b0:26f:c155:85b8 with SMTP id z8-20020a05651c022800b0026fc15585b8mr3668913ljn.220.1665999358893;
        Mon, 17 Oct 2022 02:35:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2103:b0:4a2:3951:eac8 with SMTP id
 q3-20020a056512210300b004a23951eac8ls715088lfr.0.-pod-prod-gmail; Mon, 17 Oct
 2022 02:35:57 -0700 (PDT)
X-Received: by 2002:a05:6512:31d4:b0:4a2:7709:db05 with SMTP id j20-20020a05651231d400b004a27709db05mr3589225lfe.544.1665999357687;
        Mon, 17 Oct 2022 02:35:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665999357; cv=none;
        d=google.com; s=arc-20160816;
        b=nldWTxncYmQ1RQRhiNGTAgA3YYu74j5HcnMwP7c+EPlgerIjkL9637k6sUcsbeJ1QE
         MNDofaR0BpkgUU0rGuwpnnOZJQZIaNgmtF+47S0yvX8AKVDtgj+7xvmgSTkgHnAdpv0w
         Ul/qYZa0sLEVHeYMfEVagPIcvEA4lsNPK5vqZk2uSt/PBrvlp8tgkROqV5Gbnb5sTbd7
         vPiDHGaF3lBKNO7BuYcSbW07bEC+LKf+3x95Q8oE/8AEr0ZZMW8+OxPDgf9MVQZ14moq
         DCTaslwif2XqhZPHuXxszkwxGl74CCvpkol00AQrf48nBb1JAMbiKseIjXtY9MHXK5s1
         aALA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=I/Ia4Mu9P3WluH4Bz+JF+Xw7+A6qmCSA4W2Y2iXMlFQ=;
        b=lnMR10e1tSRiBgWZtO7i3It4YFif1kDtAiyoy/h7YPjroCwfEi5PcEWBizzeesxJws
         0fyTSF5YZZrbUpz8DJvSa4H6xBiQUedwSbxLTxot4TR7hkygYdrq0GScD1qGdBKDnyrw
         Dm5LckFvXQvU8s8ZdyZFJxU7nv/pP8bfVGYgJQKqSSOLPa+lXn0wuKW/yCpv3i9Q5BIN
         cRqxcS2oNZbYvWyxPuNkAPOmkbPambF/k0Nev8aepFCauv4DfkY3j1qDuC5Kam3KTmeE
         hgY80z66YsyUe/iFZK++0gznqhgZHMWxId5MvoK4Fr8hwZJF0K9bE7jEm3SWYp8J9rn6
         snOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=VDo8Gm0J;
       spf=pass (google.com: domain of quwenruo.btrfs@gmx.com designates 212.227.15.15 as permitted sender) smtp.mailfrom=quwenruo.btrfs@gmx.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.com
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id e6-20020a05651236c600b004a225e3ed13si331313lfs.13.2022.10.17.02.35.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Oct 2022 02:35:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of quwenruo.btrfs@gmx.com designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from [0.0.0.0] ([149.28.201.231]) by mail.gmx.net (mrgmx005
 [212.227.17.184]) with ESMTPSA (Nemesis) id 1MKKUv-1oPoym2jZn-00LjgT; Mon, 17
 Oct 2022 11:35:52 +0200
Message-ID: <cae729f9-beea-ee04-1258-af393a858430@gmx.com>
Date: Mon, 17 Oct 2022 17:35:39 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.3
Subject: Re: [PATCH RFC 3/7] fs/btrfs: support `DISABLE_FS_CSUM_VERIFICATION`
 config option
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>, Qu Wenruo <wqu@suse.com>
Cc: Hrutvik Kanabar <hrkanabar@gmail.com>,
 Hrutvik Kanabar <hrutvik@google.com>, Marco Elver <elver@google.com>,
 Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
 Alexander Viro <viro@zeniv.linux.org.uk>, linux-fsdevel@vger.kernel.org,
 linux-kernel@vger.kernel.org, Theodore Ts'o <tytso@mit.edu>,
 Andreas Dilger <adilger.kernel@dilger.ca>, linux-ext4@vger.kernel.org,
 Chris Mason <clm@fb.com>, Josef Bacik <josef@toxicpanda.com>,
 David Sterba <dsterba@suse.com>, linux-btrfs@vger.kernel.org,
 Jaegeuk Kim <jaegeuk@kernel.org>, Chao Yu <chao@kernel.org>,
 linux-f2fs-devel@lists.sourceforge.net, "Darrick J . Wong"
 <djwong@kernel.org>, linux-xfs@vger.kernel.org,
 Namjae Jeon <linkinjeon@kernel.org>, Sungjong Seo <sj1557.seo@samsung.com>,
 Anton Altaparmakov <anton@tuxera.com>, linux-ntfs-dev@lists.sourceforge.net
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
 <20221014084837.1787196-4-hrkanabar@gmail.com>
 <5bc906b3-ccb5-a385-fcb6-fc51c8fea3fd@suse.com>
 <CACT4Y+YeSOZPN+ek6vSLhsCugJ3iGF35-sghnZt4qQJ36DA6mA@mail.gmail.com>
From: Qu Wenruo <quwenruo.btrfs@gmx.com>
In-Reply-To: <CACT4Y+YeSOZPN+ek6vSLhsCugJ3iGF35-sghnZt4qQJ36DA6mA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Provags-ID: V03:K1:R4tyK64oAk8yCJaovO8g6oIFOJ5yd0Mfld/q5wiz3kozqAwQUUS
 lpgS3cewdkbxgGeIFdnIcJLSyw3DqgqbHpMKqkq6iJMDWQK1v8r2vvpX8VoMHsrP7DJzziP
 MYTzi+9IfSzLElj6vjzmhop3w/xfDdajdqG4Xl7WiHTNsXM1dH86NANfkatxFl0VWhtQtc1
 LOWc73mYiVifySUhyiVYA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:P1Pf1vCA0Mo=:LdaK1AhKGgP6q3daQ1FgI+
 pBcZQ2/DqDbjSM/ch5Bo8GYYN5CIdcdy1krTo/c2d5EJLZaP7Ni+/vSh+QDYg8icdsJzrEJiV
 DyhpToTTOzaXYJHOfA/lkrQv03DT75BxKUcYYGw5z41+bZYilmhVlbDTEqV51rSB4lEQZWNkt
 gSv/3W+Kada62LM/xmsqFbFxex/RhjpOJjOz8kNWvnZX0gjjFS9cFs/k3PvcftPS4hTuhZG4w
 bftmdmcvxl3nDA88VlLFErj1cauYmH25vb0EQav9S5jO6XH4lPrAyseyUAlFXrtisV/PLH1ix
 Lr9t4TaaY1zXcO1xp7HBUKiOWI9f7DFv2LrulsEIizyYbV2JnHM11d/+upCrurY0QxNHq84ex
 EVJti0tJkcKvD+Je3sVxY7AkYJy69BqLjTzjqg7m2TaeB067VcveHqZgLhBkdVQ0bGLuwkvk7
 Gl5LA2uk9fwN9UzfBJA4d2ZJCGXE98HgeuyflZtJXL9pdJ7NNIdRY0Z4wAvUAO0QvFkmOtpCc
 zLk4KQu0sQom8HAzsZ80k2k//aHIjvfQ85lPWGYd0aQ1Ruz7FGTF+Mj1zXDFSOuGoKQAZ5Q2m
 YP7LNRSpMc9EP+hRceIdZUGd30O9ZQXYn+6u1L8IYfveqpqt9LbRCjzhuStZfrgDhh6ksWhzM
 GvOd24jy/UInX8Ie6LvqRk2igDeD8MXO0jzINQFZtbORPazSPd4tgmxZscp+SspyB3sVGHLlH
 HgWG0POeE0WOJ3HGjCSXA2ALMZ5MBDO0iwT2bJEknvt0HYviM5XJnV4c5KFVZn5UDtyopx3la
 raCwLOuRATRwc4cTbdoaTzo1XtAL/9JgyJIetUjGKyvZThZXPAhzgw1OgF2+w5Ct6bB0riOuu
 L/J4A+/Tmbet6i6U82+uDBbFeZcb7foWMdNdbRA9RdMKHhT+UXJuhNZEnnulLaf4pNwPBJMOk
 rpYdO9DiqW2bOxfHUVA5RUYrK4rrZMvnmiQ74XbvRGfpo2n4tq1KbJ2YCGDRq9IriS6QUl+WC
 i/lSljuZ7uOzf12RV7xD6we04YJ/imFRkMVxs4CjQKBAFc2q9ACwSDR2Xd0cSS68Og1UIuMBn
 61ALYMrd+wpPJcWbsG/76iN4SWlNye+A5svFDNfPSXLRUZYG0ukwegZr42+XlCCdK66ZEpuUA
 pkfUQVP5DciSSjxxW7NDON2BpahQ8jXq2OEbBeDKLaFVPG3lGdGt3vitfVoFqpb64rT+VGiLT
 Nf9hKGyDJ6O/AIFia3vUtEVE1VCHWoptVZcnMr3EjUwOkpPBISVqxh3NrYxfKqvhPZoLhEwSq
 NVvxK077sqqzQEdMrbxDx+FPG2JpS09q3z8NOyWs50rH0sYij6SkNDkN6gKRVLROpN8VJUCHB
 r3HCMIP1FWt6fJvB+UbEoTwOMypf+E+bukt/DG7PGLhO40nlidAdaUXlH1XaE39QnDYHetpAI
 Xa2bohRAwJVZMHI2pm2o6kSS+7/Se9dJSlJT+wViLdYj0TXA482aaFGEacRWLW+aXU1ylU65+
 yhaQqDUkEWCkmpa48nEPvmw2M0s2+k3ac4/v1BuqYzq8R
X-Original-Sender: quwenruo.btrfs@gmx.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=VDo8Gm0J;       spf=pass
 (google.com: domain of quwenruo.btrfs@gmx.com designates 212.227.15.15 as
 permitted sender) smtp.mailfrom=quwenruo.btrfs@gmx.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=gmx.com
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



On 2022/10/17 16:43, Dmitry Vyukov wrote:
> On Fri, 14 Oct 2022 at 12:24, 'Qu Wenruo' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> On 2022/10/14 16:48, Hrutvik Kanabar wrote:
>>> From: Hrutvik Kanabar <hrutvik@google.com>
>>>
>>> When `DISABLE_FS_CSUM_VERIFICATION` is enabled, bypass checksum
>>> verification.
>>>
>>> Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
>>
>> I always want more fuzz for btrfs, so overall this is pretty good.
>>
>> But there are some comments related to free space cache part.
>>
>> Despite the details, I'm wondering would it be possible for your fuzzing
>> tool to do a better job at user space? Other than relying on loosen
>> checks from kernel?
>>
>> For example, implement a (mostly) read-only tool to do the following
>> workload:
>>
>> - Open the fs
>>     Including understand the checksum algo, how to re-generate the csum.
>>
>> - Read out the used space bitmap
>>     In btrfs case, it's going to read the extent tree, process the
>>     backrefs items.
>>
>> - Choose the victim sectors and corrupt them
>>     Obviously, vitims should be choosen from above used space bitmap.
>>
>> - Re-calculate the checksum for above corrupted sectors
>>     For btrfs, if it's a corrupted metadata, re-calculate the checksum.
>>
>> By this, we can avoid such change to kernel, and still get a much better
>> coverage.
>>
>> If you need some help on such user space tool, I'm pretty happy to
>> provide help.
>>
>>> ---
>>>    fs/btrfs/check-integrity.c  | 3 ++-
>>>    fs/btrfs/disk-io.c          | 6 ++++--
>>>    fs/btrfs/free-space-cache.c | 3 ++-
>>>    fs/btrfs/inode.c            | 3 ++-
>>>    fs/btrfs/scrub.c            | 9 ++++++---
>>>    5 files changed, 16 insertions(+), 8 deletions(-)
>>>
>>> diff --git a/fs/btrfs/check-integrity.c b/fs/btrfs/check-integrity.c
>>> index 98c6e5feab19..eab82593a325 100644
>>> --- a/fs/btrfs/check-integrity.c
>>> +++ b/fs/btrfs/check-integrity.c
>>> @@ -1671,7 +1671,8 @@ static noinline_for_stack int btrfsic_test_for_metadata(
>>>                crypto_shash_update(shash, data, sublen);
>>>        }
>>>        crypto_shash_final(shash, csum);
>>> -     if (memcmp(csum, h->csum, fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(csum, h->csum, fs_info->csum_size))
>>>                return 1;
>>>
>>>        return 0; /* is metadata */
>>> diff --git a/fs/btrfs/disk-io.c b/fs/btrfs/disk-io.c
>>> index a2da9313c694..7cd909d44b24 100644
>>> --- a/fs/btrfs/disk-io.c
>>> +++ b/fs/btrfs/disk-io.c
>>> @@ -184,7 +184,8 @@ static int btrfs_check_super_csum(struct btrfs_fs_info *fs_info,
>>>        crypto_shash_digest(shash, raw_disk_sb + BTRFS_CSUM_SIZE,
>>>                            BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, result);
>>>
>>> -     if (memcmp(disk_sb->csum, result, fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(disk_sb->csum, result, fs_info->csum_size))
>>>                return 1;
>>>
>>>        return 0;
>>> @@ -494,7 +495,8 @@ static int validate_extent_buffer(struct extent_buffer *eb)
>>>        header_csum = page_address(eb->pages[0]) +
>>>                get_eb_offset_in_page(eb, offsetof(struct btrfs_header, csum));
>>>
>>> -     if (memcmp(result, header_csum, csum_size) != 0) {
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(result, header_csum, csum_size) != 0) {
>>
>> I believe this is the main thing fuzzing would take advantage of.
>>
>> It would be much better if this is the only override...
>>
>>>                btrfs_warn_rl(fs_info,
>>>    "checksum verify failed on logical %llu mirror %u wanted " CSUM_FMT " found " CSUM_FMT " level %d",
>>>                              eb->start, eb->read_mirror,
>>> diff --git a/fs/btrfs/free-space-cache.c b/fs/btrfs/free-space-cache.c
>>> index f4023651dd68..203c8a9076a6 100644
>>> --- a/fs/btrfs/free-space-cache.c
>>> +++ b/fs/btrfs/free-space-cache.c
>>> @@ -574,7 +574,8 @@ static int io_ctl_check_crc(struct btrfs_io_ctl *io_ctl, int index)
>>>        io_ctl_map_page(io_ctl, 0);
>>>        crc = btrfs_crc32c(crc, io_ctl->orig + offset, PAGE_SIZE - offset);
>>>        btrfs_crc32c_final(crc, (u8 *)&crc);
>>> -     if (val != crc) {
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         val != crc) {
>>
>> I'm already seeing this to cause problems, especially for btrfs.
>>
>> Btrfs has a very strong dependency on free space tracing, as all of our
>> metadata (and data by default) relies on COW to keep the fs consistent.
>>
>> I tried a lot of different methods in the past to make sure we won't
>> write into previously used space, but it's causing a lot of performance
>> impact.
>>
>> Unlike tree-checker, we can not easily got a centerlized space to handle
>> all the free space cross-check thing (thus it's only verified by things
>> like btrfs-check).
>>
>> Furthermore, even if you skip this override, with latest default
>> free-space-tree feature, free space info is stored in regular btrfs
>> metadata (tree blocks), with regular metadata checksum protection.
>>
>> Thus I'm pretty sure we will have tons of reports on this, and
>> unfortunately we can only go whac-a-mole way for it.
>
> Hi Qu,
>
> I don't fully understand what you mean. Could you please elaborate?
>
> Do you mean that btrfs uses this checksum check to detect blocks that
> were written to w/o updating the checksum?

I mean, btrfs uses this particular checksum for its (free) space cache,
and currently btrfs just trust the space cache completely to do COW.

This means, if we ignore the checksum for free space cache, we can
easily screw up the COW, e.g. allocate a range for the new metadata to
be written into.

But the truth is, that range is still being utilized by some other
metadata. Thus would completely break COW.


This is indeed a problem for btrfs, but it is not that easiy to fix,
since this involves cross-check 3 different data (free space cache for
free space, extent tree for used space, and the metadata itself).

Thus my concern is, disabling free space cache csum can easily lead to
various crashes, all related to broken COW, and we don't have a good
enough way to validate the result.

>
>
>
>
>>>                btrfs_err_rl(io_ctl->fs_info,
>>>                        "csum mismatch on free space cache");
>>>                io_ctl_unmap_page(io_ctl);
>>> diff --git a/fs/btrfs/inode.c b/fs/btrfs/inode.c
>>> index b0807c59e321..1a49d897b5c1 100644
>>> --- a/fs/btrfs/inode.c
>>> +++ b/fs/btrfs/inode.c
>>> @@ -3434,7 +3434,8 @@ int btrfs_check_sector_csum(struct btrfs_fs_info *fs_info, struct page *page,
>>>        crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
>>>        kunmap_local(kaddr);
>>>
>>> -     if (memcmp(csum, csum_expected, fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(csum, csum_expected, fs_info->csum_size))
>>
>> This skips data csum check, I don't know how valueable it is, but this
>> should be harmless mostly.
>>
>> If we got reports related to this, it would be a nice surprise.
>>
>>>                return -EIO;
>>>        return 0;
>>>    }
>>> diff --git a/fs/btrfs/scrub.c b/fs/btrfs/scrub.c
>>> index f260c53829e5..a7607b492f47 100644
>>> --- a/fs/btrfs/scrub.c
>>> +++ b/fs/btrfs/scrub.c
>>> @@ -1997,7 +1997,8 @@ static int scrub_checksum_data(struct scrub_block *sblock)
>>>
>>>        crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
>>>
>>> -     if (memcmp(csum, sector->csum, fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(csum, sector->csum, fs_info->csum_size))
>>
>> Same as data csum verification overide.
>> Not necessary/useful but good to have.
>>
>>>                sblock->checksum_error = 1;
>>>        return sblock->checksum_error;
>>>    }
>>> @@ -2062,7 +2063,8 @@ static int scrub_checksum_tree_block(struct scrub_block *sblock)
>>>        }
>>>
>>>        crypto_shash_final(shash, calculated_csum);
>>> -     if (memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
>>
>> This is much less valueable, since it's only affecting scrub, and scrub
>> itself is already very little checking the content of metadata.
>
> Could you please elaborate here as well?

These checksum verification is only done in the scrub path (just as the
file name indicates).

> This is less valuable from what perspective?

It's just much harder to trigger, regular filesystem operations won't go
into scrub path.

Unless there is also a full ioctl fuzzing tests, after corrupting the image.

> The data loaded from disk can have any combination of
> (correct/incorrect metadata) x (correct/incorrect checksum).
> Correctness of metadata and checksum are effectively orthogonal,

Oh, I almost forgot another problem with the compile time csum
verification skip.

If we skip csum check completely, just like the patch, it may cause less
path coverage (this is very btrfs specific)

The problem is, btrfs has some repair path (scrub, and read-time), which
requires to have a checksum mismatch (and a good copy with good checksum).

Thus if we ignore csum completely, the repair path will never be covered
(as we treat them all as csum match).

Thanks,
Qu

> right?
>
>
>
>> Thanks,
>> Qu
>>
>>>                sblock->checksum_error = 1;
>>>
>>>        return sblock->header_error || sblock->checksum_error;
>>> @@ -2099,7 +2101,8 @@ static int scrub_checksum_super(struct scrub_block *sblock)
>>>        crypto_shash_digest(shash, kaddr + BTRFS_CSUM_SIZE,
>>>                        BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, calculated_csum);
>>>
>>> -     if (memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
>>> +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
>>> +         memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
>>>                ++fail_cor;
>>>
>>>        return fail_cor + fail_gen;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cae729f9-beea-ee04-1258-af393a858430%40gmx.com.
