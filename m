Return-Path: <kasan-dev+bncBDUNBGN3R4KRB6NZXKPAMGQEN4YN3WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74AD1677E4A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 15:43:06 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id y21-20020a056402359500b0049e171c4ad0sf8529253edc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 06:43:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674484986; cv=pass;
        d=google.com; s=arc-20160816;
        b=cxZw5e50gqrddcJ5pYPB1jyloZkjaC/HfrSyWw18plb/Ay/Ni+ahhYIYF7BSSi7e2S
         MWo28xpdLGacfERMjceKSCfAQwZ6bKVdLuKfTffbsMVzAeEBObcxCggcouKFym5pJdSq
         og0WofYbBP0CK88/VbmRby9HrgG6BLxzM7ZG+Kpthe5QXr7N5nMWR7FuCmtn8wwGOz65
         RlxjuN6PNVW3zXVSUhyVff1nZZdeKp6yD0FRqtHdv81yr7DvdJuqjMBt1n+1EuwDnq9w
         QhhfEWMcFAbtCb4kQiE4m7ka7qsT9OUV97rMtnAR1/yocqPtdO3BlB/uLVa38RPzzI8M
         /VWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DNaUvC51dnhFfrgD0uqONLr9W0wgH3sSrXiPk5wVMAk=;
        b=zpIGZ6kLSBNqF8O3naUITdvl3wrVGX64FeFocF8JfskJmoTqWDXGDxqpdwm4loy7jh
         cBLls5sRe4K8lTzlu9uJ2d4/GzzymYDIrkZwjsZCQDOoxbqHkAsZ88z+27TStdy+ebgn
         Yr5mgCtWSo3/bGtAIFBe2Yts9m7ie3svLJ3H6oZeM5sZaxF6jgD+60F1VvgbG6ATBpfq
         3RyBPqDo6O/W6jv1/qbMk5p9hgMCKJOn2cyUHhzFo3bW5eqqb0sLnDPvkGf/xUL/rAdj
         gNJpics8C9sLs1RhjPwCr23Vkfk4hi/fMr5I191xgMPTPPUVpUDBrxba3w+itxaukM2U
         dIrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DNaUvC51dnhFfrgD0uqONLr9W0wgH3sSrXiPk5wVMAk=;
        b=jrx05cm+3Es7Htjy0MwAXeDvTpKZLCsYP5nIOaQmdKonKMJZk8l0cr7BlbBbF8lBdS
         oj0NHWxbNkUqKIKbfm9rhGZKbHBh9yHPgxLgRSW6Yyz9fQOTfm+GTZHaqCx3c039A+Z7
         9kOHZzJLFXzbZaYc5Ls/CH/Kjzs7XLs1MOKH+uLkGgzr62Zniz1K5b00rQdCqBLDIK45
         KqEDdj0+91KNmxZ8YPjIsGOcFVey4gCMDpUhx0BLW92yX330PsBESq3ix40eaOGfEMN8
         xzGsxDZSs9I8ICD0s9DrmTrLAE2jXLJd7y5/Nhf6fGZeqK/Q60dXRwzZWuOIS7wJLvP6
         R4IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DNaUvC51dnhFfrgD0uqONLr9W0wgH3sSrXiPk5wVMAk=;
        b=LShGymCsSOXkg/XSYbeFUeo5YmWyvohPC3J+iPRtjNDN3DozRdYTiOPpjWVXJaQ7CU
         URy8jmurpUFgg2yVWjwRq6rRH2Aj1xPN/TmXrIHKoDH56xTLQGJAAU6pT9RtNkgkrGPO
         Y/6KfL7GFVYjWaZOd9NOjmUbBU2a5jeGg7AMhYrbELZatymVwgLythGbwbf/MhMrQFMk
         99AtCAGBZsk/u4Qp53IjMVCvVrDEnjP+rkDk6OEeksTY1jDCryqkOMTyCOr4Pw87l/TD
         bNTkTXdJDhUfTJRqnx6bKNxogbsvIsbLYd66CHjMEsne/3/owHNjmVdli5nFk7a7Qebx
         gVqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koOCvZxz+tZP9kynPR87xz0H8LM9s8hKUuvnbxCDTuj0bp1HchY
	iTU33xhKlm9lxt33QmkhxnE=
X-Google-Smtp-Source: AMrXdXvjLG9thMxSk4W0QK+kfA49jsy8RulOXdoqyTRC/JKHOp9nAmnwFTctIs1q28A2/gcMLyitew==
X-Received: by 2002:a17:906:7d8f:b0:7c0:e0db:f136 with SMTP id v15-20020a1709067d8f00b007c0e0dbf136mr2402770ejo.333.1674484985874;
        Mon, 23 Jan 2023 06:43:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2691:b0:49e:29ce:a2b with SMTP id
 w17-20020a056402269100b0049e29ce0a2bls8172604edd.0.-pod-prod-gmail; Mon, 23
 Jan 2023 06:43:04 -0800 (PST)
X-Received: by 2002:a05:6402:4305:b0:49c:7aa2:55de with SMTP id m5-20020a056402430500b0049c7aa255demr33682841edc.1.1674484984540;
        Mon, 23 Jan 2023 06:43:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674484984; cv=none;
        d=google.com; s=arc-20160816;
        b=d70RGRGqWjSdwmhnJc1YRdGvnENYIEht00w/YDPsZ3kfobKfhRPX7D8jdt1AiogcrK
         9Xns71R7JGruMZGHc1lV9hq3d7PV4vT1TphGPLU/Pj9KbG7K/IOaXYwrX9dXZaeqmNrV
         ZabEca2eysI2ziKCPn8T52p5dmrKHVXTt5U9wvCNvnGCiEXAfROCOjy9lTAydConlIf7
         dO+5/MFGi+f09pqRMUsyOFxbrH1H2CMQhEK+7NW0iusti3qcFifR1xuLwowud78HDBB6
         lEQ4+T/o9I6oqI4OkJ/7yJlxLFnjcEN26oppzCbcqI4RXEVomSPGLBBLsbVSIbC2T16m
         m4hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=fwo5GffP8KsynnMNpf79tUE5ko/tH2KBo6xdBDgEFig=;
        b=MvS3+ebYeXRzZvHzjhphAPBPZcZ2E+FTXJj92W87Eb56q91FBDSDzKb07CKdsKL9sy
         KDdoacwl2uf8UQLpY4aPN8+s3Ptr9QMUJdUhubzkGyEb2He1/F9NUm4rZUTRHi35aKwS
         wQpFnglzc47B5zNcEhzV8l3pSqyJSzfsMwJCxBV/bypRAD1Rx78mdWpSBGpXIz7BPZaW
         kGkpQwqXteQ+QCcJwlehC4OTMU8XhJc+/8s5K8n1k/9goXkyV9ofh2ikXcU/E949WdKt
         lXKzZ7hjucErXKTZMH5cuNAegGI0okI3h2jBLWXzRXmHHq6J9yprzHHS6riqYw7jzNPN
         whFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id q30-20020a056402249e00b0049ecd39787fsi399437eda.5.2023.01.23.06.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Jan 2023 06:43:04 -0800 (PST)
Received-SPF: none (google.com: lst.de does not designate permitted sender hosts) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 99D8C68C7B; Mon, 23 Jan 2023 15:43:01 +0100 (CET)
Date: Mon, 23 Jan 2023 15:43:01 +0100
From: Christoph Hellwig <hch@lst.de>
To: David Hildenbrand <david@redhat.com>
Cc: Christoph Hellwig <hch@lst.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH 05/10] mm: call vfree instead of __vunmap from
 delayed_vfree_work
Message-ID: <20230123144301.GA31126@lst.de>
References: <20230121071051.1143058-1-hch@lst.de> <20230121071051.1143058-6-hch@lst.de> <96cd68be-674f-8def-b82c-a0e17256ed05@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <96cd68be-674f-8def-b82c-a0e17256ed05@redhat.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
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

On Mon, Jan 23, 2023 at 11:38:46AM +0100, David Hildenbrand wrote:
> On 21.01.23 08:10, Christoph Hellwig wrote:
>> This adds an extra, never taken,  in_interrupt() branch, but will allow
>> to cut down the maze of vfree helpers.
>>
>> Reviewed-by: Christoph Hellwig <hch@lst.de>
>
> Self-review? :) I assume that was supposed to be a Signed-off-by ...


Yes, this should be a singoff:

Signed-off-by: Christoph Hellwig <hch@lst.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123144301.GA31126%40lst.de.
